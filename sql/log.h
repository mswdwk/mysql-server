/* Copyright (c) 2005, 2013, Oracle and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

#ifndef LOG_H
#define LOG_H

#include "unireg.h"                    // REQUIRED: for other includes
#include "sql_class.h"
#include "handler.h"                            /* my_xid */


/**
  Transaction Coordinator Log.

  A base abstract class for three different implementations of the
  transaction coordinator.

  The server uses the transaction coordinator to order transactions
  correctly and there are three different implementations: one using
  an in-memory structure, one dummy that does not do anything, and one
  using the binary log for transaction coordination.
*/
class TC_LOG
{
  public:
  int using_heuristic_recover();
  TC_LOG() {}
  virtual ~TC_LOG() {}

  enum enum_result {
    RESULT_SUCCESS,
    RESULT_ABORTED,
    RESULT_INCONSISTENT
  };

  virtual int open(const char *opt_name)=0;
  virtual void close()=0;

  /**
     Log a commit record of the transaction to the transaction
     coordinator log.

     When the function returns, the transaction commit is properly
     logged to the transaction coordinator log and can be committed in
     the storage engines.

     @param thd Session to log transaction for.
     @param all @c True if this is a "real" commit, @c false if it is a "statement" commit.

     @return Error code on failure, zero on success.
   */
  virtual enum_result commit(THD *thd, bool all) = 0;

  /**
     Log a rollback record of the transaction to the transaction
     coordinator log.

     When the function returns, the transaction have been aborted in
     the transaction coordinator log.

     @param thd Session to log transaction record for.

     @param all @c true if an explicit commit or an implicit commit
     for a statement, @c false if an internal commit of the statement.

     @return Error code on failure, zero on success.
   */
  virtual int rollback(THD *thd, bool all) = 0;
  /**
     Log a prepare record of the transaction to the storage engines.

     @param thd Session to log transaction record for.

     @param all @c true if an explicit commit or an implicit commit
     for a statement, @c false if an internal commit of the statement.

     @return Error code on failure, zero on success.
   */
  virtual int prepare(THD *thd, bool all) = 0;
};


class TC_LOG_DUMMY: public TC_LOG // use it to disable the logging
{
public:
  TC_LOG_DUMMY() {}
  int open(const char *opt_name)        { return 0; }
  void close()                          { }
  enum_result commit(THD *thd, bool all) {
    return ha_commit_low(thd, all) ? RESULT_ABORTED : RESULT_SUCCESS;
  }
  int rollback(THD *thd, bool all) {
    return ha_rollback_low(thd, all);
  }
  int prepare(THD *thd, bool all) {
    return ha_prepare_low(thd, all);
  }
};

class TC_LOG_MMAP: public TC_LOG
{
public:                // only to keep Sun Forte on sol9x86 happy
  typedef enum {
    PS_POOL,                 // page is in pool
    PS_ERROR,                // last sync failed
    PS_DIRTY                 // new xids added since last sync
  } PAGE_STATE;

private:
  typedef struct st_page {
    struct st_page *next; // pages are linked in a fifo queue
    my_xid *start, *end;  // usable area of a page
    my_xid *ptr;          // next xid will be written here
    int size, free;       // max and current number of free xid slots on the page
    int waiters;          // number of waiters on condition
    PAGE_STATE state;     // see above
    /**
      Signalled when syncing of this page is done or when
      this page is in "active" slot and syncing slot just
      became free.
    */
    mysql_cond_t  cond;
  } PAGE;

  char logname[FN_REFLEN];
  File fd;
  my_off_t file_length;
  uint npages, inited;
  uchar *data;
  struct st_page *pages, *syncing, *active, *pool, **pool_last_ptr;
  /*
    LOCK_tc is used to protect access both to data members 'syncing',
    'active', 'pool' and to the content of PAGE objects.
  */
  mysql_mutex_t LOCK_tc;
  /**
    Signalled when active PAGE is moved to syncing state,
    thus member "active" becomes 0.
  */
  mysql_cond_t COND_active;
  /**
    Signalled when one more page becomes available in the
    pool which we might select as active.
  */
  mysql_cond_t COND_pool;

public:
  TC_LOG_MMAP(): inited(0) {}
  int open(const char *opt_name);
  void close();
  enum_result commit(THD *thd, bool all);
  int rollback(THD *thd, bool all)      { return ha_rollback_low(thd, all); }
  int prepare(THD *thd, bool all)       { return ha_prepare_low(thd, all); }
  int recover();
  uint size() const;

private:
  ulong log_xid(my_xid xid);
  void unlog(ulong cookie, my_xid xid);
  PAGE* get_active_from_pool();
  bool sync();
  void overflow();

protected:
  // We want to mock away syncing to disk in unit tests.
  virtual int do_msync_and_fsync(int fd_arg, void *addr, size_t len, int flags)
  {
    return my_msync(fd_arg, addr, len, flags);
  }

private:
  /**
    Find empty slot in the page and write xid value there.

    @param   xid    value of xid to store in the page
    @param   p      pointer to the page where to store xid
    @param   data   pointer to the top of the mapped to memory file
                    to calculate offset value (cookie)

    @return  offset value from the top of the page where the xid was stored.
  */
  ulong store_xid_in_empty_slot(my_xid xid, PAGE *p, uchar *data_arg)
  {
    /* searching for an empty slot */
    while (*p->ptr)
    {
      p->ptr++;
      DBUG_ASSERT(p->ptr < p->end);               // because p->free > 0
    }

    /* found! store xid there and mark the page dirty */
    ulong cookie= (ulong)((uchar *)p->ptr - data_arg);      // can never be zero
    *p->ptr++= xid;
    p->free--;
    p->state= PS_DIRTY;

    return cookie;
  }

  /**
    Wait for until page data will be written to the disk.

    @param   p   pointer to the PAGE to store to the disk

    @return
      @retval false   Success
      @retval true    Failure
  */
  bool wait_sync_completion(PAGE *p)
  {
    p->waiters++;
    while (p->state == PS_DIRTY && syncing)
    {
      mysql_cond_wait(&p->cond, &LOCK_tc);
    }
    p->waiters--;

    return p->state == PS_ERROR;
  }

  /*
    the following friend declaration is to grant access from TCLogMMapTest
    to methods log_xid()/unlog() that are private.
  */
  friend class TCLogMMapTest;
};

extern TC_LOG *tc_log;
extern TC_LOG_MMAP tc_log_mmap;
extern TC_LOG_DUMMY tc_log_dummy;


////////////////////////////////////////////////////////////
//
// Slow/General Log
//
////////////////////////////////////////////////////////////

/*
  System variables controlling logging:

  log_output (--log-output)
    Values: NONE, FILE, TABLE
    Select output destination. Does not enable logging.
    Can set more than one (e.g. TABLE | FILE).

  general_log (--general_log)
  slow_query_log (--slow_query_log)
    Values: 0, 1
    Enable/disable general/slow query log.

  general_log_file (--general-log-file)
  slow_query_log_file (--slow-query-log-file)
    Values: filename
    Set name of general/slow query log file.

  sql_log_off
    Values: ON, OFF
    Enable/disable general query log (OPTION_LOG_OFF).

  log_queries_not_using_indexes (--log-queries-not-using-indexes)
    Values: ON, OFF
    Control slow query logging of queries that do not use indexes.

  --log-raw
    Values: ON, OFF
    Control query rewrite of passwords to the general log.

  --log-short-format
    Values: ON, OFF
    Write short format to the slow query log (and the binary log).

  --log-slow-admin-statements
    Values: ON, OFF
    Log statements such as OPTIMIZE TABLE, ALTER TABLE to the slow query log.

  --log-slow-slave-statements
    Values: ON, OFF

  log_throttle_queries_not_using_indexes
    Values: INT
    Number of queries not using indexes logged to the slow query log per min.
*/


class Query_logger;
class Log_to_file_event_handler;

/** Type of the log table */
enum enum_log_table_type
{
  QUERY_LOG_NONE = 0,
  QUERY_LOG_SLOW = 1,
  QUERY_LOG_GENERAL = 2
};

class File_query_log
{
  File_query_log(enum_log_table_type log_type)
  : m_log_type(log_type), name(NULL), write_error(false), log_open(false)
  {
    memset(&log_file, 0, sizeof(log_file));
    mysql_mutex_init(key_LOG_LOCK_log, &LOCK_log, MY_MUTEX_INIT_SLOW);
#ifdef HAVE_PSI_INTERFACE
    if (log_type == QUERY_LOG_GENERAL)
      m_log_file_key= key_file_general_log;
    else if (log_type == QUERY_LOG_SLOW)
      m_log_file_key= key_file_slow_log;
#endif
  }

  ~File_query_log()
  {
    DBUG_ASSERT(!is_open());
    mysql_mutex_destroy(&LOCK_log);
  }

  /** @return true if the file log is open, false otherwise. */
  bool is_open() const { return log_open; }

  /**
     Open a (new) log file.

     Open the logfile, init IO_CACHE and write startup messages.

     @return true if error, false otherwise.
  */
  bool open();

  /**
     Close the log file

     @note One can do an open on the object at once after doing a close.
     The internal structures are not freed until the destructor is called.
  */
  void close();

  /**
     Check if we have already printed ER_ERROR_ON_WRITE and if not,
     do so.
  */
  void check_and_print_write_error();

  /**
     Write a command to traditional general log file.
     Log given command to normal (not rotatable) log file.

     @param event_utime       Command start timestamp in micro seconds
     @param user_host         The pointer to the string with user@host info
     @param user_host_len     Length of the user_host string. this is computed once
                              and passed to all general log event handlers
     @param thread_id         Id of the thread that issued the query
     @param command_type      The type of the command being logged
     @param command_type_len  The length of the string above
     @param sql_text          The very text of the query being executed
     @param sql_text_len      The length of sql_text string

     @return true if error, false otherwise.
  */
  bool write_general(ulonglong event_utime, const char *user_host,
                     size_t user_host_len, my_thread_id thread_id,
                     const char *command_type, size_t command_type_len,
                     const char *sql_text, size_t sql_text_len);

  /**
     Log a query to the traditional slow log file.

     @param thd               THD of the query
     @param current_utime     Current timestamp in micro seconds
     @param query_start_arg   Command start timestamp
     @param user_host         The pointer to the string with user@host info
     @param user_host_len     Length of the user_host string. this is computed once
                              and passed to all general log event handlers
     @param query_utime       Amount of time the query took to execute (in microseconds)
     @param lock_utime        Amount of time the query was locked (in microseconds)
     @param is_command        The flag which determines whether the sql_text is a
                              query or an administrator command.
     @param sql_text          The very text of the query or administrator command
                              processed
     @param sql_text_len      The length of sql_text string

     @return true if error, false otherwise.
*/
  bool write_slow(THD *thd, ulonglong current_utime, ulonglong query_start_arg,
                  const char *user_host, size_t user_host_len,
                  ulonglong query_utime, ulonglong lock_utime, bool is_command,
                  const char *sql_text, size_t sql_text_len);

private:
  /** Type of log file. */
  const enum_log_table_type m_log_type;

  /** Makes sure we only have one write at a time. */
  mysql_mutex_t LOCK_log;

  /** Log filename. */
  char *name;

  /** Path to log file. */
  char log_file_name[FN_REFLEN];

  /** Last seen current database. */
  char db[NAME_LEN + 1];

  /** Have we already printed ER_ERROR_ON_WRITE? */
  bool write_error;

  IO_CACHE log_file;

  /** True if the file log is open, false otherwise. */
  volatile bool log_open;

#ifdef HAVE_PSI_INTERFACE
  /** Instrumentation key to use for file io in @c log_file */
  PSI_file_key m_log_file_key;
#endif

  friend class Log_to_file_event_handler;
  friend class Query_logger;
};


/**
   Abstract superclass for handling logging to slow/general logs.
   Currently has two subclasses, for table and file based logging.
*/
class Log_event_handler
{
public:
  Log_event_handler() {}
  virtual ~Log_event_handler() {}

  /**
     Log a query to the slow log.

     @param thd               THD of the query
     @param current_utime     Current timestamp in micro seconds
     @param query_start_arg   Command start timestamp in micro seconds
     @param user_host         The pointer to the string with user@host info
     @param user_host_len     Length of the user_host string. this is computed once
                              and passed to all general log event handlers
     @param query_time        Amount of time the query took to execute (in microseconds)
     @param lock_time         Amount of time the query was locked (in microseconds)
     @param is_command        The flag which determines whether the sql_text is a
                              query or an administrator command (these are treated
                              differently by the old logging routines)
     @param sql_text          The very text of the query or administrator command
                              processed
     @param sql_text_len      The length of sql_text string

     @retval  false   OK
     @retval  true    error occured
  */
  virtual bool log_slow(THD *thd, ulonglong current_utime,
                        ulonglong query_start_arg, const char *user_host,
                        size_t user_host_len, ulonglong query_utime,
                        ulonglong lock_utime, bool is_command,
                        const char *sql_text, size_t sql_text_len)= 0;

  /**
     Log command to the general log.

     @param  event_utime       Command start timestamp in micro seconds
     @param  user_host         The pointer to the string with user@host info
     @param  user_host_len     Length of the user_host string. this is computed
                               once and passed to all general log event handlers
     @param  thread_id         Id of the thread, issued a query
     @param  command_type      The type of the command being logged
     @param  command_type_len  The length of the string above
     @param  sql_text          The very text of the query being executed
     @param  sql_text_len      The length of sql_text string

     @return This function attempts to never call my_error(). This is
     necessary, because general logging happens already after a statement
     status has been sent to the client, so the client can not see the
     error anyway. Besides, the error is not related to the statement
     being executed and is internal, and thus should be handled
     internally (@todo: how?).
     If a write to the table has failed, the function attempts to
     write to a short error message to the file. The failure is also
     indicated in the return value.

     @retval  false   OK
     @retval  true    error occured
  */
  virtual bool log_general(THD *thd, ulonglong event_utime, const char *user_host,
                           size_t user_host_len, my_thread_id thread_id,
                           const char *command_type, size_t command_type_len,
                           const char *sql_text, size_t sql_text_len,
                           const CHARSET_INFO *client_cs)= 0;
};


/** Class responsible for table based logging. */
class Log_to_csv_event_handler: public Log_event_handler
{
public:
  /** @see Log_event_handler::log_slow(). */
  virtual bool log_slow(THD *thd, ulonglong current_utime,
                        ulonglong query_start_arg, const char *user_host,
                        size_t user_host_len, ulonglong query_utime,
                        ulonglong lock_utime, bool is_command,
                        const char *sql_text, size_t sql_text_len);

  /** @see Log_event_handler::log_general(). */
  virtual bool log_general(THD *thd, ulonglong event_utime, const char *user_host,
                           size_t user_host_len, my_thread_id thread_id,
                           const char *command_type, size_t command_type_len,
                           const char *sql_text, size_t sql_text_len,
                           const CHARSET_INFO *client_cs);

private:
  /**
     Check if log table for given log type exists and can be opened.

     @param thd       Thread handle
     @param log_type  QUERY_LOG_SLOW or QUERY_LOG_GENERAL

     @return true if table could not be opened, false otherwise.
  */
  bool activate_log(THD *thd, enum_log_table_type log_type);

  friend class Query_logger;
};


/**
   Class responsible for file based logging.
   Basically a wrapper around File_query_log.
*/
class Log_to_file_event_handler: public Log_event_handler
{
  File_query_log mysql_general_log;
  File_query_log mysql_slow_log;

public:
  /**
     Wrapper around File_query_log::write_slow() for slow log.
     @see Log_event_handler::log_slow().
  */
  virtual bool log_slow(THD *thd, ulonglong current_utime,
                        ulonglong query_start_arg, const char *user_host,
                        size_t user_host_len, ulonglong query_utime,
                        ulonglong lock_utime, bool is_command,
                        const char *sql_text, size_t sql_text_len);

  /**
     Wrapper around File_query_log::write_general() for general log.
     @see Log_event_handler::log_general().
  */
  virtual bool log_general(THD *thd, ulonglong event_utime, const char *user_host,
                           size_t user_host_len, my_thread_id thread_id,
                           const char *command_type, size_t command_type_len,
                           const char *sql_text, size_t sql_text_len,
                           const CHARSET_INFO *client_cs);

private:
  Log_to_file_event_handler()
    : mysql_general_log(QUERY_LOG_GENERAL),
    mysql_slow_log(QUERY_LOG_SLOW)
  { }

  /** Close slow and general log files. */
  void cleanup()
  {
    mysql_general_log.close();
    mysql_slow_log.close();
  }

  /** @return File_query_log instance responsible for writing to slow/general log.*/
  File_query_log *get_query_log(enum_log_table_type log_type)
  {
    if (log_type == QUERY_LOG_SLOW)
      return &mysql_slow_log;
    DBUG_ASSERT(log_type == QUERY_LOG_GENERAL);
    return &mysql_general_log;
  }

  friend class Query_logger;
};


/* Log event handler flags */
static const uint LOG_NONE= 1;
static const uint LOG_FILE= 2;
static const uint LOG_TABLE= 4;


/** Class which manages slow and general log event handlers. */
class Query_logger
{
  /**
     Currently we have only 2 kinds of logging functions: old-fashioned
     file logs and csv logging routines.
  */
  static const uint MAX_LOG_HANDLERS_NUM= 2;

  /** Max size of the log message. */
  static const uint MAX_LOG_BUFFER_SIZE= 1024;

  /**
     RW-lock protecting Query_logger.
     R-lock taken when writing to slow/general query log.
     W-lock taken when activating/deactivating logs.
  */
  mysql_rwlock_t LOCK_logger;

  /** Available log handlers. */
  Log_to_csv_event_handler table_log_handler;
  Log_to_file_event_handler *file_log_handler;

  /** NULL-terminated arrays of log handlers. */
  Log_event_handler *slow_log_handler_list[MAX_LOG_HANDLERS_NUM + 1];
  Log_event_handler *general_log_handler_list[MAX_LOG_HANDLERS_NUM + 1];

private:
  /**
     Setup log event handlers for the given log_type.

     @param log_type     QUERY_LOG_SLOW or QUERY_LOG_GENERAL
     @param log_printer  Bitmap of LOG_NONE, LOG_FILE, LOG_TABLE
  */
  void init_query_log(enum_log_table_type log_type, ulonglong log_printer);

public:
  Query_logger()
    : file_log_handler(NULL)
  { }

  /**
     Check if table logging is turned on for the given log_type.

     @param log_type  QUERY_LOG_SLOW or QUERY_LOG_GENERAL

     @return true if table logging is on, false otherwise.
  */
  bool is_log_table_enabled(enum_log_table_type log_type) const
  {
    if (log_type == QUERY_LOG_SLOW)
      return (opt_slow_log && (log_output_options & LOG_TABLE));
    else if (log_type == QUERY_LOG_GENERAL)
      return (opt_general_log && (log_output_options & LOG_TABLE));
    DBUG_ASSERT(false);
    return false;                             /* make compiler happy */
  }

  /**
     Check if file logging is turned on for the given log type.

     @param log_type  QUERY_LOG_SLOW or QUERY_LOG_GENERAL

     @return true if the file logging is on, false otherwise.
  */
  bool is_log_file_enabled(enum_log_table_type log_type) const
  { return file_log_handler->get_query_log(log_type)->is_open(); }

  /**
     Perform basic log initialization: create file-based log handler.

     We want to initialize all log mutexes as soon as possible,
     but we cannot do it in constructor, as safe_mutex relies on
     initialization, performed by MY_INIT(). This why this is done in
     this function.
  */
  void init()
  {
    file_log_handler= new Log_to_file_event_handler; // Causes mutex init
    mysql_rwlock_init(key_rwlock_LOCK_logger, &LOCK_logger);
  }

  /** Free memory. Nothing could be logged after this function is called. */
  void cleanup();

  /**
     Log slow query with all enabled log event handlers.

     @param thd           THD of the statement being logged.
     @param query         The query string being logged.
     @param query_length  The length of the query string.

     @return true if error, false otherwise.
  */
  bool slow_log_write(THD *thd, const char *query, size_t query_length);

  /**
     Write printf style message to general query log.

     @param thd           THD of the statement being logged.
     @param command       COM of statement being logged.
     @param format        Printf style format of message.
     @param ...           Printf parameters to write.

     @return true if error, false otherwise.
  */
  bool general_log_print(THD *thd, enum_server_command command,
                         const char *format, ...);

  /**
     Write query to general query log.

     @param thd           THD of the statement being logged.
     @param command       COM of statement being logged.
     @param query         The query string being logged.
     @param query_length  The length of the query string.

     @return true if error, false otherwise.
  */
  bool general_log_write(THD *thd, enum_server_command command,
                         const char *query, size_t query_length);

  /**
     Enable log event handlers for slow/general log.

     @param log_printer     Bitmask of log event handlers.

     @note Acceptable values are LOG_NONE, LOG_FILE, LOG_TABLE
  */
  void set_handlers(ulonglong log_printer);

  /**
     Activate log handlers for the given log type.

     @param thd       Thread handle
     @param log_type  QUERY_LOG_SLOW or QUERY_LOG_GENERAL

     @return true if error, false otherwise.
  */
  bool activate_log_handler(THD *thd, enum_log_table_type log_type);

  /**
     Close file log for the given log type.

     @param log_type  QUERY_LOG_SLOW or QUERY_LOG_GENERAL
  */
  void deactivate_log_handler(enum_log_table_type log_type);

  /**
     Close file log for the given log type and the reopen it.

     @param log_type  QUERY_LOG_SLOW or QUERY_LOG_GENERAL
  */
  bool reopen_log_file(enum_log_table_type log_type);

  /**
     Check if given TABLE_LIST has a query log table name and
     optionally check if the query log is currently enabled.

     @param table_list       TABLE_LIST representing the table to check
     @param check_if_opened  Always return QUERY_LOG_NONE unless the
                             query log table is enabled.

     @retval QUERY_LOG_NONE, QUERY_LOG_SLOW or QUERY_LOG_GENERAL
  */
  enum_log_table_type check_if_log_table(TABLE_LIST *table_list,
                                         bool check_if_opened) const;
};

extern Query_logger query_logger;

/**
   Create the name of the query log specified.

   This method forms a new path + file name for the log specified.

   @param[in] buff      Location for building new string.
   @param[in] log_type  QUERY_LOG_SLOW or QUERY_LOG_GENERAL

   @returns Pointer to new string containing the name.
*/
char *make_query_log_name(char *buff, enum_log_table_type log_type);

/**
  Check whether we need to write the current statement (or its rewritten
  version if it exists) to the slow query log.
  As a side-effect, a digest of suppressed statements may be written.

  @param thd          thread handle

  @retval
    true              statement needs to be logged
  @retval
    false             statement does not need to be logged
*/
bool log_slow_applicable(THD *thd);

/**
  Unconditionally writes the current statement (or its rewritten version if it
  exists) to the slow query log.

  @param thd              thread handle
*/
void log_slow_do(THD *thd);

/**
  Check whether we need to write the current statement to the slow query
  log. If so, do so. This is a wrapper for the two functions above;
  most callers should use this wrapper.  Only use the above functions
  directly if you have expensive rewriting that you only need to do if
  the query actually needs to be logged (e.g. SP variables / NAME_CONST
  substitution when executing a PROCEDURE).
  A digest of suppressed statements may be logged instead of the current
  statement.

  @param thd              thread handle
*/
void log_slow_statement(THD *thd);


#ifdef MYSQL_SERVER // Security_context not defined otherwise.

/**
  @class Log_throttle
  @brief Base class for rate-limiting a log (slow query log etc.)
*/

class Log_throttle
{
  /**
    When will/did current window end?
  */
  ulonglong window_end;

  /**
    Log no more than rate lines of a given type per window_size
    (e.g. per minute, usually LOG_THROTTLE_WINDOW_SIZE).
  */
  const ulong window_size;

  /**
   There have been this many lines of this type in this window,
   including those that we suppressed. (We don't simply stop
   counting once we reach the threshold as we'll write a summary
   of the suppressed lines later.)
  */
  ulong count;

protected:
  /**
    Template for the summary line. Should contain %lu as the only
    conversion specification.
  */
  const char *summary_template;

  /**
    Start a new window.
  */
  void new_window(ulonglong now);

  /**
    Increase count of logs we're handling.

    @param rate  Limit on records to be logged during the throttling window.

    @retval true -  log rate limit is exceeded, so record should be supressed.
    @retval false - log rate limit is not exceeded, record should be logged.
  */
  bool inc_log_count(ulong rate) { return (++count > rate); }

  /**
    Check whether we're still in the current window. (If not, the caller
    will want to print a summary (if the logging of any lines was suppressed),
    and start a new window.)
  */
  bool in_window(ulonglong now) const { return (now < window_end); };

  /**
    Prepare a summary of suppressed lines for logging.
    This function returns the number of queries that were qualified for
    inclusion in the log, but were not printed because of the rate-limiting.
    The summary will contain this count as well as the respective totals for
    lock and execution time.
    This function assumes that the caller already holds the necessary locks.

    @param rate  Limit on records logged during the throttling window.
  */
  ulong prepare_summary(ulong rate);

  /**
    @param window_usecs  ... in this many micro-seconds
    @param msg           use this template containing %lu as only non-literal
  */
  Log_throttle(ulong window_usecs, const char *msg)
              : window_end(0), window_size(window_usecs),
                count(0), summary_template(msg)
  {}

public:
  /**
    We're rate-limiting messages per minute; 60,000,000 microsecs = 60s
    Debugging is less tedious with a window in the region of 5000000
  */
  static const ulong LOG_THROTTLE_WINDOW_SIZE= 60000000;
};


/**
  @class Slow_log_throttle
  @brief Used for rate-limiting the slow query log.
*/

class Slow_log_throttle : public Log_throttle
{
private:
  /**
    We're using our own (empty) security context during summary generation.
    That way, the aggregate value of the suppressed queries isn't printed
    with a specific user's name (i.e. the user who sent a query when or
    after the time-window closes), as that would be misleading.
  */
  Security_context aggregate_sctx;

  /**
    Total of the execution times of queries in this time-window for which
    we suppressed logging. For use in summary printing.
  */
  ulonglong total_exec_time;

  /**
    Total of the lock times of queries in this time-window for which
    we suppressed logging. For use in summary printing.
  */
  ulonglong total_lock_time;

  /**
    A reference to the threshold ("no more than n log lines per ...").
    References a (system-?) variable in the server.
  */
  ulong *rate;

  /**
    The routine we call to actually log a line (i.e. our summary).
    The signature miraculously coincides with slow_log_print().
  */
  bool (*log_summary)(THD *, const char *, size_t);

  /**
    Slow_log_throttle is shared between THDs.
  */
  mysql_mutex_t *LOCK_log_throttle;

  /**
    Start a new window.
  */
  void new_window(ulonglong now);

  /**
    Actually print the prepared summary to log.
  */
  void print_summary(THD *thd, ulong suppressed,
                     ulonglong print_lock_time,
                     ulonglong print_exec_time);

public:

  /**
    @param threshold     suppress after this many queries ...
    @param window_usecs  ... in this many micro-seconds
    @param logger        call this function to log a single line (our summary)
    @param msg           use this template containing %lu as only non-literal
  */
  Slow_log_throttle(ulong *threshold, mysql_mutex_t *lock, ulong window_usecs,
                    bool (*logger)(THD *, const char *, size_t),
                    const char *msg);

  /**
    Prepare and print a summary of suppressed lines to log.
    (For now, slow query log.)
    The summary states the number of queries that were qualified for
    inclusion in the log, but were not printed because of the rate-limiting,
    and their respective totals for lock and execution time.
    This wrapper for prepare_summary() and print_summary() handles the
    locking/unlocking.

    @param thd                 The THD that tries to log the statement.
    @retval false              Logging was not supressed, no summary needed.
    @retval true               Logging was supressed; a summary was printed.
  */
  bool flush(THD *thd);

  /**
    Top-level function.
    @param thd                 The THD that tries to log the statement.
    @param eligible            Is the statement of the type we might suppress?
    @retval true               Logging should be supressed.
    @retval false              Logging should not be supressed.
  */
  bool log(THD *thd, bool eligible);
};


/**
  @class Slow_log_throttle
  @brief Used for rate-limiting a error logs.
*/

class Error_log_throttle : public Log_throttle
{
private:
  /**
    The routine we call to actually log a line (i.e. our summary).
  */
  void (*log_summary)(const char *, ...);

  /**
    Actually print the prepared summary to log.
  */
  void print_summary(ulong suppressed)
  {
    (*log_summary)(summary_template, suppressed);
  }

public:
  /**
    @param window_usecs  ... in this many micro-seconds
    @param logger        call this function to log a single line (our summary)
    @param msg           use this template containing %lu as only non-literal
  */
  Error_log_throttle(ulong window_usecs,
                     void (*logger)(const char*, ...),
                     const char *msg)
  : Log_throttle(window_usecs, msg), log_summary(logger)
  {}

  /**
    Prepare and print a summary of suppressed lines to log.
    (For now, slow query log.)
    The summary states the number of queries that were qualified for
    inclusion in the log, but were not printed because of the rate-limiting.

    @retval false              Logging was not suppressed, no summary needed.
    @retval true               Logging was suppressed; a summary was printed.
  */
  bool flush();

  /**
    Top-level function.
    @retval true               Logging should be suppressed.
    @retval false              Logging should not be suppressed.
  */
  bool log();
};


extern Slow_log_throttle log_throttle_qni;

enum enum_mts_parallel_type {
  /* Parallel slave based on Database name */
  MTS_PARALLEL_TYPE_DB_NAME= 0,
  /* Parallel slave based on group information from Binlog group commit */
  MTS_PARALLEL_TYPE_LOGICAL_CLOCK= 1
};


#endif // MYSQL_SERVER

////////////////////////////////////////////////////////////
//
// Error Log
//
////////////////////////////////////////////////////////////

/**
   Prints a printf style error message to the error log.
   @see error_log_print
*/
void sql_print_error(const char *format, ...)
  __attribute__((format(printf, 1, 2)));

/**
   Prints a printf style warning message to the error log.
   @see error_log_print
*/
void sql_print_warning(const char *format, ...)
  __attribute__((format(printf, 1, 2)));

/**
   Prints a printf style information message to the error log.
   @see error_log_print
*/
void sql_print_information(const char *format, ...)
  __attribute__((format(printf, 1, 2)));

/**
   Prints a printf style message to the error log and, under NT, to the
   Windows event log.

   This function prints the message into a buffer and then sends that buffer
   to other functions to write that message to other logging sources.

   @param level          The level of the msg significance
   @param format         Printf style format of message
   @param args           va_list list of arguments for the message
*/
void error_log_print(enum loglevel level, const char *format, va_list args);

/**
  Change the file associated with two output streams. Used to
  redirect stdout and stderr to a file. The streams are reopened
  only for appending (writing at end of file).
*/
bool reopen_fstreams(const char *filename, FILE *outstream, FILE *errstream);

bool flush_error_log();

#endif /* LOG_H */
