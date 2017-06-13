/* Copyright (c) 2006, 2017, Oracle and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   51 Franklin Street, Suite 500, Boston, MA 02110-1335 USA */

#ifndef RPL_MI_H
#define RPL_MI_H

#include <sys/types.h>
#include <time.h>

#include "m_string.h"
#include "my_inttypes.h"
#include "my_io.h"
#include "my_psi_config.h"
#include "mysql/psi/mysql_mutex.h"
#include "mysql/psi/psi_base.h"
#include "mysql_com.h"
#include "sql_const.h"

class Relay_log_info;
class Rpl_info_handler;
class Server_ids;
class THD;

#include "binlog_event.h"            // enum_binlog_checksum_alg
#include "log_event.h"               // Format_description_log_event
#include "rpl_gtid.h"                // Gtid
#include "rpl_info.h"                // Rpl_info
#include "rpl_trx_boundary_parser.h" // Transaction_boundary_parser
#include "rpl_rli.h"                 // rli->get_log_lock()

typedef struct st_mysql MYSQL;

#define DEFAULT_CONNECT_RETRY 60

/*****************************************************************************
  Replication IO Thread

  Master_info contains:
    - information about how to connect to a master
    - current master log name
    - current master log offset
    - misc control variables

  Master_info is initialized once from the master.info repository if such
  exists. Otherwise, data members corresponding to master.info fields
  are initialized with defaults specified by master-* options. The
  initialization is done through mi_init_info() call.

  Logically, the format of master.info repository is presented as follows:

  log_name
  log_pos
  master_host
  master_user
  master_pass
  master_port
  master_connect_retry

  To write out the contents of master.info to disk a call to flush_info()
  is required. Currently, it is needed every time we read and queue data
  from the master.

  To clean up, call end_info()

*****************************************************************************/

class Master_info : public Rpl_info, public Gtid_mode_copy
{
friend class Rpl_info_factory;

public:
  /**
    Host name or ip address stored in the master.info.
  */
  char host[HOSTNAME_LENGTH + 1];

  /*
    Check if the channel is configured.

    @param mi Pointer to Master_info.

    @retval true  The channel is configured.
    @retval false The channel is not configured.
  */
  static bool is_configured(Master_info *mi)
  {
    return mi && mi->host[0];
  }

private:
  /**
    If true, USER/PASSWORD was specified when running START SLAVE.
  */
  bool start_user_configured;
  /**
    User's name stored in the master.info.
  */
  char user[USERNAME_LENGTH + 1];
  /**
    User's password stored in the master.info.
  */
  char password[MAX_PASSWORD_LENGTH + 1]; 
  /**
    User specified when running START SLAVE.
  */
  char start_user[USERNAME_LENGTH + 1];
  /**
    Password specified when running START SLAVE.
  */
  char start_password[MAX_PASSWORD_LENGTH + 1]; 
  /**
    Stores the autentication plugin specified when running START SLAVE.
  */
  char start_plugin_auth[FN_REFLEN + 1];
  /**
    Stores the autentication plugin directory specified when running
    START SLAVE.
  */
  char start_plugin_dir[FN_REFLEN + 1];

  /// Information on the current and last queued transactions
  Gtid_monitoring_info *gtid_monitoring_info;

public:
  /**
    Returns if USER/PASSWORD was specified when running
    START SLAVE.

    @return true or false.
  */
  bool is_start_user_configured() const
  {
    return start_user_configured;
  }
  /**
    Returns if DEFAULT_AUTH was specified when running START SLAVE.

    @return true or false.
  */
  bool is_start_plugin_auth_configured() const
  {
    return (start_plugin_auth[0] != 0);
  }
  /**
    Returns if PLUGIN_DIR was specified when running START SLAVE.

    @return true or false.
  */
  bool is_start_plugin_dir_configured() const
  {
    return (start_plugin_dir[0] != 0);
  }
  /**
    Defines that USER/PASSWORD was specified or not when running
    START SLAVE.

    @param config is true or false.
  */
  void set_start_user_configured(bool config)
  {
    start_user_configured= config;
  }
  /**
    Sets either user's name in the master.info repository when CHANGE
    MASTER is executed or user's name used in START SLAVE if USER is
    specified.

    @param user_arg is user's name.
  */
  void set_user(const char* user_arg)
  {
    if (user_arg && start_user_configured)
    {
      strmake(start_user, user_arg, sizeof(start_user) - 1);
    }
    else if (user_arg)
    {
      strmake(user, user_arg, sizeof(user) - 1);
    }
  }
  /**
    Returns user's size name. See @c get_user().

    @return user's size name.
  */
  size_t get_user_size() const
  {
    return (start_user_configured ? sizeof(start_user) : sizeof(user));
  }
  /**
    If an user was specified when running START SLAVE, this function returns
    such user. Otherwise, it returns the user stored in master.info.

    @return user's name.
  */
  const char *get_user() const
  {
    return start_user_configured ? start_user : user;
  } 
  /**
    Stores either user's password in the master.info repository when CHANGE
    MASTER is executed or user's password used in START SLAVE if PASSWORD
    is specified.

    @param password_arg is user's password.

  */
  void set_password(const char* password_arg);
  /**
    Returns either user's password in the master.info repository or
    user's password used in START SLAVE.

    @param[out] password_arg is user's password.
    @param[out] password_arg_size is user's password size.

    @return false if there is no error, otherwise true is returned.
  */
  bool get_password(char *password_arg, size_t *password_arg_size);
  /**
    Cleans in-memory password defined by START SLAVE.
  */
  void reset_start_info();
  /**
    Returns the DEFAULT_AUTH defined by START SLAVE.

    @return DEFAULT_AUTH.
  */
  const char *get_start_plugin_auth()
  {
    return start_plugin_auth;
  }
  /**
    Returns the PLUGIN_DIR defined by START SLAVE.

    @return PLUGIN_DIR.
  */
  const char *get_start_plugin_dir()
  {
    return start_plugin_dir;
  }
  /**
    Stores the DEFAULT_AUTH defined by START SLAVE.
  */
  void set_plugin_auth(const char* src)
  {
    if (src)
      strmake(start_plugin_auth, src, sizeof(start_plugin_auth) - 1);
  }
  /**
    Stores the DEFAULT_AUTH defined by START SLAVE.
  */
  void set_plugin_dir(const char* src)
  {
    if (src)
      strmake(start_plugin_dir, src, sizeof(start_plugin_dir) - 1);
  }

  bool ssl; // enables use of SSL connection if true
  char ssl_ca[FN_REFLEN], ssl_capath[FN_REFLEN], ssl_cert[FN_REFLEN];
  char ssl_cipher[FN_REFLEN], ssl_key[FN_REFLEN], tls_version[FN_REFLEN];
  char ssl_crl[FN_REFLEN], ssl_crlpath[FN_REFLEN];
  bool ssl_verify_server_cert;

  MYSQL* mysql;
  uint32 file_id;				/* for 3.23 load data infile */
  Relay_log_info *rli;
  uint port;
  uint connect_retry;
  /*
     The difference in seconds between the clock of the master and the clock of
     the slave (second - first). It must be signed as it may be <0 or >0.
     clock_diff_with_master is computed when the I/O thread starts; for this the
     I/O thread does a SELECT UNIX_TIMESTAMP() on the master.
     "how late the slave is compared to the master" is computed like this:
     clock_of_slave - last_timestamp_executed_by_SQL_thread - clock_diff_with_master

  */
  long clock_diff_with_master;
  float heartbeat_period;         // interface with CHANGE MASTER or master.info
  ulonglong received_heartbeats;  // counter of received heartbeat events

  ulonglong last_heartbeat;

  Server_ids *ignore_server_ids;

  ulong master_id;
  /*
    to hold checksum alg in use until IO thread has received FD.
    Initialized to novalue, then set to the queried from master
    @@global.binlog_checksum and deactivated once FD has been received.
  */
  binary_log::enum_binlog_checksum_alg checksum_alg_before_fd;
  ulong retry_count;
  char master_uuid[UUID_LENGTH+1];
  char bind_addr[HOSTNAME_LENGTH+1];

  int mi_init_info();
  void end_info();
  int flush_info(bool force= FALSE);
  void set_relay_log_info(Relay_log_info *info);

  bool shall_ignore_server_id(ulong s_id);

  /*
     A buffer to hold " for channel <channel_name>
     used in error messages per channel
   */
  char for_channel_str[CHANNEL_NAME_LENGTH+15];
  char for_channel_uppercase_str[CHANNEL_NAME_LENGTH+15];

  /**
    @return The pointer to the Gtid_monitoring_info
  */
  Gtid_monitoring_info* get_gtid_monitoring_info()
  {
    return gtid_monitoring_info;
  }

  /**
    Stores the details of the transaction the receiver thread has just started
    queueing.

    @param  gtid_arg         the gtid of the trx
    @param  original_ts_arg  the original commit timestamp of the transaction
    @param  immediate_ts_arg the immediate commit timestamp of the transaction
  */
  void started_queueing(Gtid gtid_arg, ulonglong original_ts_arg,
                        ulonglong immediate_ts_arg)
  {
    gtid_monitoring_info->start(gtid_arg, original_ts_arg, immediate_ts_arg);
  }

  /**
    When the receiver thread finishes queueing a transaction, that timestamp
    is recorded and the information is copied to last_queued_trx and cleared
    from queueing_trx.
  */
  void finished_queueing()
  {
    gtid_monitoring_info->finish();
  }

  /**
    @return True if there is a transaction currently being queued
  */
  bool is_queueing_trx()
  {
    return gtid_monitoring_info->is_processing_trx_set();
  }

  /**
    @return The pointer to the GTID of the processing_trx of
            Gtid_monitoring_info.
  */
  const Gtid* get_queueing_trx_gtid()
  {
    return gtid_monitoring_info->get_processing_trx_gtid();
  }

  /**
    Clears the processing_trx monitoring info.

    Normally called when there is an error while queueing the transaction.
  */
  void clear_queueing_trx(bool need_lock=false)
  {
    if (need_lock)
      mysql_mutex_lock(&data_lock);
    gtid_monitoring_info->clear_processing_trx();
    if (need_lock)
      mysql_mutex_unlock(&data_lock);
  }

  /**
    Clears all GTID monitoring info.
  */
  void clear_gtid_monitoring_info(bool need_lock=false)
  {
    if (need_lock)
      mysql_mutex_lock(&data_lock);
    gtid_monitoring_info->clear();
    if (need_lock)
      mysql_mutex_unlock(&data_lock);
  }


  virtual ~Master_info();

protected:
  char master_log_name[FN_REFLEN];
  my_off_t master_log_pos;

public:
  inline const char* get_master_log_name() { return master_log_name; }
  inline ulonglong get_master_log_pos() { return master_log_pos; }
  inline void set_master_log_name(const char *log_file_name)
  {
    strmake(master_log_name, log_file_name, sizeof(master_log_name) - 1);
  }
  inline void set_master_log_pos(ulonglong log_pos)
  {
    master_log_pos= log_pos;
  }
  inline const char* get_io_rpl_log_name()
  {
    return (master_log_name[0] ? master_log_name : "FIRST");
  }
  static size_t get_number_info_mi_fields();

  /**
     returns the column number of a channel in the TABLE repository.
     Mainly used during server startup to load the information required
     from the slave repostiory tables. See rpl_info_factory.cc
  */
  static uint get_channel_field_num();

  /**
     Returns an array with the expected column names of the primary key
     fields of the table repository.
  */
  static const char **get_table_pk_field_names();

  /**
     Returns an array with the expected column numbers of the primary key
     fields of the table repository.
  */
  static const uint *get_table_pk_field_indexes();

  bool is_auto_position()
  {
    return auto_position;
  }

  void set_auto_position(bool auto_position_param)
  {
    auto_position= auto_position_param;
  }

private:
  /**
    Format_description_log_event for events received from the master
    by the IO thread and written to the tail of the relay log.

    Use patterns:
     - Created when the IO thread starts and destroyed when the IO
       thread stops.
     - Updated when the IO thread receives a
       Format_description_log_event.
     - Accessed by the IO thread when it de-serializes events (e.g.,
       rotate events, Gtid events).
     - Written by the IO thread to the new relay log on every rotation.
     - Written by a client that executes FLUSH LOGS to the new relay
       log on every rotation.

    Locks:
    All access is protected by Relay_log::LOCK_log.
  */
  Format_description_log_event *mi_description_event;
public:
  Format_description_log_event *get_mi_description_event()
  {
    mysql_mutex_assert_owner(rli->relay_log.get_log_lock());
    return mi_description_event;
  }
  void set_mi_description_event(Format_description_log_event *fdle)
  {
    mysql_mutex_assert_owner(rli->relay_log.get_log_lock());
    delete mi_description_event;
    mi_description_event= fdle;
  }

  bool set_info_search_keys(Rpl_info_handler *to);

  virtual const char* get_for_channel_str(bool upper_case= false) const
  {
    return reinterpret_cast<const char *>(upper_case ?
                                          for_channel_uppercase_str
                                          : for_channel_str);
  }

  void init_master_log_pos();
private:

  bool read_info(Rpl_info_handler *from);
  bool write_info(Rpl_info_handler *to);

  bool auto_position;

  Master_info(
#ifdef HAVE_PSI_INTERFACE
              PSI_mutex_key *param_key_info_run_lock,
              PSI_mutex_key *param_key_info_data_lock,
              PSI_mutex_key *param_key_info_sleep_lock,
              PSI_mutex_key *param_key_info_thd_lock,
              PSI_mutex_key *param_key_info_data_cond,
              PSI_mutex_key *param_key_info_start_cond,
              PSI_mutex_key *param_key_info_stop_cond,
              PSI_mutex_key *param_key_info_sleep_cond,
#endif
              uint param_id, const char* param_channel
             );

  Master_info(const Master_info& info);
  Master_info& operator=(const Master_info& info);

public:
  /*
    This will be used to verify transactions boundaries of events sent by the
    master server.
    It will also be used to verify transactions boundaries on the relay log
    while collecting the Retrieved_Gtid_Set to make sure of only adding GTIDs
    of fully retrieved transactions.
  */
  Transaction_boundary_parser transaction_parser;

private:
  /*
    This is the channel lock. It is a rwlock used to serialize all replication
    administrative commands that cannot be performed concurrently for a given
    replication channel:
    - START SLAVE;
    - STOP SLAVE;
    - CHANGE MASTER;
    - RESET SLAVE;
    - end_slave() (when mysqld stops)).
    Any of these commands must hold the wrlock from the start till the end.
  */
  Checkable_rwlock *m_channel_lock;

  /* References of the channel, the channel can only be deleted when it is 0. */
  std::atomic<int32> atomic_references{0};
public:
  /**
    Acquire the channel read lock.
  */
  void channel_rdlock();

  /**
    Acquire the channel write lock.
  */
  void channel_wrlock();

  /**
    Release the channel lock (whether it is a write or read lock).
  */
  inline void channel_unlock()
  { m_channel_lock->unlock(); }

  /**
    Assert that some thread holds either the read or the write lock.
  */
  inline void channel_assert_some_lock() const
  { m_channel_lock->assert_some_lock(); }

  /**
    Assert that some thread holds the write lock.
  */
  inline void channel_assert_some_wrlock() const
  { m_channel_lock->assert_some_wrlock(); }

  /**
    Increase the reference count to prohibit deleting a channel. This function
    must be protected by channel_map.rdlock(). dec_reference has to be
    called in conjunction with inc_reference().
  */
  void inc_reference() { ++atomic_references; }

  /**
    Decrease the reference count. Doesn't need the protection of
    channel_map.rdlock.
  */
  void dec_reference() { --atomic_references; }

  /**
    It mush be called before deleting a channel and protected by
    channel_map_lock.wrlock().

    @param thd the THD object of current thread
  */
  void wait_until_no_reference(THD *thd);
};

#endif /* RPL_MI_H */
