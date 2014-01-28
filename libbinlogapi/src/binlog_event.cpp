/*
Copyright (c) 2003, 2011, 2013, Oracle and/or its affiliates. All rights
reserved.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; version 2 of
the License.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
02110-1301  USA
*/

#include "binlog_event.h"
#include "transitional_methods.h"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdint.h>
#include <string.h>

const unsigned char checksum_version_split[3]= {5, 6, 1};
const unsigned long checksum_version_product=
  (checksum_version_split[0] * 256 + checksum_version_split[1]) * 256 +
  checksum_version_split[2];


namespace binary_log_debug
{
  bool debug_query_mts_corrupt_db_names= false;
  bool debug_checksum_test= false;
  bool debug_simulate_invalid_address= false;
  bool debug_pretend_version_50034_in_binlog= false;
}


/*
  Explicit instantiation to unsigned int of template available_buffer
  function.
*/
template unsigned int available_buffer<unsigned int>(const char*,
                                                     const char*,
                                                     unsigned int);

/*
  Explicit instantiation to unsigned int of template valid_buffer_range
  function.
*/
template bool valid_buffer_range<unsigned int>(unsigned int,
                                               const char*,
                                               const char*,
                                               unsigned int);
namespace binary_log
{
const char *get_event_type_str(Log_event_type type)
{
  switch(type) {
  case START_EVENT_V3:  return "Start_v3";
  case STOP_EVENT:   return "Stop";
  case QUERY_EVENT:  return "Query";
  case ROTATE_EVENT: return "Rotate";
  case INTVAR_EVENT: return "Intvar";
  case LOAD_EVENT:   return "Load";
  case NEW_LOAD_EVENT:   return "New_load";
  case SLAVE_EVENT:  return "Slave";
  case CREATE_FILE_EVENT: return "Create_file";
  case APPEND_BLOCK_EVENT: return "Append_block";
  case DELETE_FILE_EVENT: return "Delete_file";
  case EXEC_LOAD_EVENT: return "Exec_load";
  case RAND_EVENT: return "RAND";
  case XID_EVENT: return "Xid";
  case USER_VAR_EVENT: return "User var";
  case FORMAT_DESCRIPTION_EVENT: return "Format_desc";
  case TABLE_MAP_EVENT: return "Table_map";
  case PRE_GA_WRITE_ROWS_EVENT: return "Write_rows_event_old";
  case PRE_GA_UPDATE_ROWS_EVENT: return "Update_rows_event_old";
  case PRE_GA_DELETE_ROWS_EVENT: return "Delete_rows_event_old";
  case WRITE_ROWS_EVENT_V1: return "Write_rows_v1";
  case UPDATE_ROWS_EVENT_V1: return "Update_rows_v1";
  case DELETE_ROWS_EVENT_V1: return "Delete_rows_v1";
  case BEGIN_LOAD_QUERY_EVENT: return "Begin_load_query";
  case EXECUTE_LOAD_QUERY_EVENT: return "Execute_load_query";
  case INCIDENT_EVENT: return "Incident";
  case IGNORABLE_LOG_EVENT: return "Ignorable";
  case ROWS_QUERY_LOG_EVENT: return "Rows_query";
  case WRITE_ROWS_EVENT: return "Write_rows";
  case UPDATE_ROWS_EVENT: return "Update_rows";
  case DELETE_ROWS_EVENT: return "Delete_rows";
  case GTID_LOG_EVENT: return "Gtid";
  case ANONYMOUS_GTID_LOG_EVENT: return "Anonymous_Gtid";
  case PREVIOUS_GTIDS_LOG_EVENT: return "Previous_gtids";
  case HEARTBEAT_LOG_EVENT: return "Heartbeat";
  default: return "Unknown";
  }
  return "No Error";
}


/**
   The method returns the checksum algorithm used to checksum the binary log.
   For MySQL server versions < 5.6, the algorithm is undefined. For the higher
   versions, the type is decoded from the FORMAT_DESCRIPTION_EVENT.

   @param buf buffer holding serialized FD event
   @param len netto (possible checksum is stripped off) length of the event buf

   @return  the version-safe checksum alg descriptor where zero
            designates no checksum, 255 - the orginator is
            checksum-unaware (effectively no checksum) and the actuall
            [1-254] range alg descriptor.
*/
enum_binlog_checksum_alg
Log_event_footer::get_checksum_alg(const char* buf, unsigned long len)
{
  enum_binlog_checksum_alg ret;
  char version[ST_SERVER_VER_LEN];
  unsigned char version_split[3];
#ifndef DBUG_OFF
  assert(buf[EVENT_TYPE_OFFSET] == FORMAT_DESCRIPTION_EVENT);
#endif
  memcpy(version, buf +
         buf[LOG_EVENT_MINIMAL_HEADER_LEN + ST_COMMON_HEADER_LEN_OFFSET]
         + ST_SERVER_VER_OFFSET, ST_SERVER_VER_LEN);
  version[ST_SERVER_VER_LEN - 1]= 0;

  do_server_version_split(version, version_split);
  if (version_product(version_split) < checksum_version_product)
    ret=  BINLOG_CHECKSUM_ALG_UNDEF;
  else
    ret= static_cast<enum_binlog_checksum_alg>(*(buf + len -
                                                 BINLOG_CHECKSUM_LEN -
                                                 BINLOG_CHECKSUM_ALG_DESC_LEN));
  assert(ret == BINLOG_CHECKSUM_ALG_OFF ||
         ret == BINLOG_CHECKSUM_ALG_UNDEF ||
         ret == BINLOG_CHECKSUM_ALG_CRC32);
  return ret;
}

/**
  Log_event_header constructor

  @param buf                  the buffer containing the complete information
                              including the event and the header data

  @param description_event    first constructor of Format_description_event,
                              used to extract the binlog_version
*/
Log_event_header::
Log_event_header(const char* buf, uint16_t binlog_version)
: data_written(0), log_pos(0)
{
  uint32_t tmp_sec= 0;
  memcpy(&tmp_sec, buf, sizeof(tmp_sec));
  when.tv_sec= le32toh(tmp_sec);
  when.tv_usec= 0;
  type_code= static_cast<Log_event_type>(buf[EVENT_TYPE_OFFSET]);
  assert (type_code < ENUM_END_EVENT);

  memcpy(&unmasked_server_id,
         buf + SERVER_ID_OFFSET, sizeof(unmasked_server_id));

  unmasked_server_id= le32toh(unmasked_server_id);

  /**
    @verbatim
    The first 13 bytes in the header is as follows:
      +============================================+
      | member_variable               offset : len |
      +============================================+
      | when.tv_sec                        0 : 4   |
      +--------------------------------------------+
      | type_code       EVENT_TYPE_OFFSET(4) : 1   |
      +--------------------------------------------+
      | server_id       SERVER_ID_OFFSET(5)  : 4   |
      +--------------------------------------------+
      | data_written    EVENT_LEN_OFFSET(9)  : 4   |
      +============================================+
    @endverbatim
   */
  memcpy(&data_written, buf + EVENT_LEN_OFFSET, 4);
  data_written= le64toh(data_written);

  memcpy(&log_pos, buf + LOG_POS_OFFSET, 4);
  log_pos= le64toh(log_pos);

  switch (binlog_version)
  {
  case 1:
    log_pos= 0;
    flags= 0;
    break;

  case 3:
    /*
      If the log is 4.0 (so here it can only be a 4.0 relay log read by
      the SQL thread or a 4.0 master binlog read by the I/O thread),
      log_pos is the beginning of the event: we transform it into the end
      of the event, which is more useful.
      But how do you know that the log is 4.0: you know it if
      description_event is version 3 *and* you are not reading a
      Format_desc (remember that mysqlbinlog starts by assuming that 5.0
      logs are in 4.0 format, until it finds a Format_desc).
    */
    if (buf[EVENT_TYPE_OFFSET] < FORMAT_DESCRIPTION_EVENT && log_pos)
    {
      /*
        If log_pos=0, don't change it. log_pos==0 is a marker to mean
        "don't change rli->group_master_log_pos" (see
        inc_group_relay_log_pos()). As it is unreal log_pos, adding the
        event len's is not correct. For example, a fake Rotate event should
        not have its log_pos (which is 0) changed or it will modify
        Exec_master_log_pos in SHOW SLAVE STATUS, displaying a wrong
        value of (a non-zero offset which does not exist in the master's
        binlog, so which will cause problems if the user uses this value
        in CHANGE MASTER).
      */
      log_pos+= data_written; /* purecov: inspected */
    }

  /* 4.0 or newer */
  /**
    @verbatim
    Additional header fields include:
      +=============================================+
      | member_variable               offset : len  |
      +=============================================+
      | log_pos           LOG_POS_OFFSET(13) : 4    |
      +---------------------------------------------+
      | flags               FLAGS_OFFSET(17) : 1    |
      +---------------------------------------------+
      | extra_headers                     19 : x-19 |
      +=============================================+
     extra_headers are not used in the current version.
    @endverbatim
   */

  default:
    memcpy(&flags, buf + FLAGS_OFFSET, sizeof(flags));
    flags= le16toh(flags);

     if ((buf[EVENT_TYPE_OFFSET] == FORMAT_DESCRIPTION_EVENT) ||
         (buf[EVENT_TYPE_OFFSET] == ROTATE_EVENT))
     {
       /*
         These events always have a header which stops here (i.e. their
         header is FROZEN).
       */
       /*
         Initialization to zero of all other Log_event members as they're
         not specified. Currently there are no such members; in the future
         there will be an event UID (but Format_description and Rotate
         don't need this UID, as they are not propagated through
         --log-slave-updates (remember the UID is used to not play a query
         twice when you have two masters which are slaves of a 3rd master).
         Then we are done with decoding the header.
      */
      break;
    }
  /* otherwise, go on with reading the header from buf (nothing now) */
  } //end switch (binlog_version)
}


/**
  Tests the checksum algorithm used for the binary log, and asserts in case
  if the checksum algorithm is invalid.

  @param   event_buf       point to the buffer containing serialized event
  @param   event_len       length of the event accounting possible
                           checksum alg
  @param   alg             checksum algorithm used for the binary log

  @retval  TRUE            if test fails
  @retval  FALSE           as success
*/
bool Log_event_footer::event_checksum_test(unsigned char *event_buf,
                                           unsigned long event_len,
                                           enum_binlog_checksum_alg alg)
{
  bool res= false;
  unsigned short flags= 0; // to store in FD's buffer flags orig value

  if (alg != BINLOG_CHECKSUM_ALG_OFF && alg != BINLOG_CHECKSUM_ALG_UNDEF)
  {
    uint32_t incoming;
    uint32_t computed;

    if (event_buf[EVENT_TYPE_OFFSET] == FORMAT_DESCRIPTION_EVENT)
    {
    #ifndef DBUG_OFF
      unsigned char fd_alg= event_buf[event_len - BINLOG_CHECKSUM_LEN -
                             BINLOG_CHECKSUM_ALG_DESC_LEN];
    #endif
      /*
        FD event is checksummed and therefore verified w/o
        the binlog-in-use flag.
      */
      memcpy(&flags, event_buf + FLAGS_OFFSET, sizeof(flags));
      flags= le16toh(flags);
      if (flags & LOG_EVENT_BINLOG_IN_USE_F)
        event_buf[FLAGS_OFFSET] &= ~LOG_EVENT_BINLOG_IN_USE_F;
      /*
         The only algorithm currently is CRC32. Zero indicates
         the binlog file is checksum-free *except* the FD-event.
      */
    #ifndef DBUG_OFF
      assert(fd_alg == BINLOG_CHECKSUM_ALG_CRC32 || fd_alg == 0);
    #endif
      assert(alg == BINLOG_CHECKSUM_ALG_CRC32);
      /*
        Complile time guard to watch over  the max number of alg
      */
      do_compile_time_assert(BINLOG_CHECKSUM_ALG_ENUM_END <= 0x80);
    }
    memcpy(&incoming,
           event_buf + event_len - BINLOG_CHECKSUM_LEN, sizeof(incoming));
    incoming= le32toh(incoming);

    computed= checksum_crc32(0L, NULL, 0);
    /* checksum the event content but not the checksum part itself */
    computed= binary_log::checksum_crc32(computed,
                                         (const unsigned char*) event_buf,
                                         event_len - BINLOG_CHECKSUM_LEN);

    if (flags != 0)
    {
      /* restoring the orig value of flags of FD */
    #ifndef DBUG_OFF
      assert(event_buf[EVENT_TYPE_OFFSET] == FORMAT_DESCRIPTION_EVENT);
    #endif
      event_buf[FLAGS_OFFSET]= flags;
    }

    res= !(computed == incoming);
  }
#ifndef DBUG_OFF
  if (binary_log_debug::debug_checksum_test)
    return true;
#endif
  return res;
}


/**
  This ctor will create a new object of Log_event_header, and initialize
  the variable m_header, which in turn will be used to initialize Log_event's
  member common_header.
  It will also advance the buffer after reading the common_header_len
*/
Binary_log_event::Binary_log_event(const char **buf, uint16_t binlog_version,
                                   const char *server_version)
: m_header(*buf, binlog_version)
{
  Format_description_event *des= new Format_description_event(binlog_version,
                                                              server_version);
  m_footer= Log_event_footer();
  // remove the comments when all the events are moved to libbinlogevent
  // (*buf)+= des->common_header_len;
  delete des;
  des= NULL;
}

/*
  The destructor is pure virtual to prevent instantiation of the class.
*/
Binary_log_event::~Binary_log_event()
{
}

/**
   Empty ctor of Start_event_v3 called when we call the
   ctor of FDE which takes binlog_version as the parameter
   It will initialize the server_version by global variable
   server_version
*/
Start_event_v3::Start_event_v3(Log_event_type type_code_arg)
: Binary_log_event(type_code_arg),
  created(0), binlog_version(BINLOG_VERSION),
  dont_set_created(0)
{
}

/**
  Format_description_log_event 1st constructor.

    This constructor can be used to create the event to write to the binary log
    (when the server starts or when FLUSH LOGS), or to create artificial events
    to parse binlogs from MySQL 3.23 or 4.x.
    When in a client, only the 2nd use is possible.

  @param binlog_ver             the binlog version for which we want to build
                                an event. Can be 1 (=MySQL 3.23), 3 (=4.0.x
                                x>=2 and 4.1) or 4 (MySQL 5.0). Note that the
                                old 4.0 (binlog version 2) is not supported;
                                it should not be used for replication with
                                5.0.
  @param server_ver             a string containing the server version.
*/
Format_description_event::Format_description_event(uint8_t binlog_ver,
                                                   const char* server_ver)
: Start_event_v3(FORMAT_DESCRIPTION_EVENT), event_type_permutation(0)
{
  binlog_version= binlog_ver;
  switch (binlog_ver) {
  case 4: /* MySQL 5.0 and above*/
  {
    memcpy(server_version, server_ver, ST_SERVER_VER_LEN);
    if (binary_log_debug::debug_pretend_version_50034_in_binlog)
      bapi_stpcpy(server_version, "5.0.34");
    common_header_len= LOG_EVENT_HEADER_LEN;
    number_of_event_types= LOG_EVENT_TYPES;
    /**
      This will be used to initialze the post_header_len,
      for binlog version 4.
    */
    static uint8_t server_event_header_length[]=
    {
      START_V3_HEADER_LEN,
      QUERY_HEADER_LEN,
      STOP_HEADER_LEN,
      ROTATE_HEADER_LEN,
      INTVAR_HEADER_LEN,
      LOAD_HEADER_LEN,
      0, /* Unused because the code for Slave log event was removed. (15th Oct. 2010) */
      CREATE_FILE_HEADER_LEN,
      APPEND_BLOCK_HEADER_LEN,
      EXEC_LOAD_HEADER_LEN,
      DELETE_FILE_HEADER_LEN,
      NEW_LOAD_HEADER_LEN,
      RAND_HEADER_LEN,
      USER_VAR_HEADER_LEN,
      FORMAT_DESCRIPTION_HEADER_LEN,
      XID_HEADER_LEN,
      BEGIN_LOAD_QUERY_HEADER_LEN,
      EXECUTE_LOAD_QUERY_HEADER_LEN,
      TABLE_MAP_HEADER_LEN,
      /*
       The PRE_GA events are never be written to any binlog, but
       their lengths are included in Format_description_log_event.
       Hence, we need to be assign some value here, to avoid reading
       uninitialized memory when the array is written to disk.
      */
      0,/* PRE_GA_WRITE_ROWS_EVENT */
      0,/* PRE_GA_UPDATE_ROWS_EVENT*/
      0,/* PRE_GA_DELETE_ROWS_EVENT*/
      ROWS_HEADER_LEN_V1, /* WRITE_ROWS_EVENT_V1*/
      ROWS_HEADER_LEN_V1, /* UPDATE_ROWS_EVENT_V1*/
      ROWS_HEADER_LEN_V1, /* DELETE_ROWS_EVENT_V1*/
      INCIDENT_HEADER_LEN,
      0,/* HEARTBEAT_LOG_EVENT*/
      IGNORABLE_HEADER_LEN,
      IGNORABLE_HEADER_LEN,
      ROWS_HEADER_LEN_V2,
      ROWS_HEADER_LEN_V2,
      ROWS_HEADER_LEN_V2,
      //TODO  25 will be replaced byGtid_log_event::POST_HEADER_LENGTH;
       25,
       25,
       IGNORABLE_HEADER_LEN
    };
    post_header_len= (uint8_t*)bapi_malloc(number_of_event_types * sizeof(uint8_t)
                                           + BINLOG_CHECKSUM_ALG_DESC_LEN);

    if (post_header_len)
    {
      /**
         Allows us to sanity-check that all events initialized their
         events (see the end of this 'if' block).
      */
      memset(post_header_len, 255, number_of_event_types * sizeof(uint8_t));
      memcpy(post_header_len, server_event_header_length, number_of_event_types);
      // Sanity-check that all post header lengths are initialized.
      for (int i= 0; i < number_of_event_types; i++)
        assert(post_header_len[i] != 255);
    }
    break;
  }
  case 1: /* 3.23 */
  case 3: /* 4.0.x x >= 2 */
  {
    /*
      We build an artificial (i.e. not sent by the master) event, which
      describes what those old master versions send.
    */
    if (server_ver[0] == '\000')
      server_ver= 0;
    if (binlog_version == 1)
      bapi_stpcpy(server_version, server_ver ? server_ver : "3.23");
    else
      bapi_stpcpy(server_version, server_ver ? server_ver : "4.0");
    common_header_len= binlog_ver == 1 ? OLD_HEADER_LEN :
      LOG_EVENT_MINIMAL_HEADER_LEN;
    /*
      The first new event in binlog version 4 is Format_desc. So any event type
      after that does not exist in older versions. We use the events known by
      version 3, even if version 1 had only a subset of them (this is not a
      problem: it uses a few bytes for nothing but unifies code; it does not
      make the slave detect less corruptions).
    */
    number_of_event_types= FORMAT_DESCRIPTION_EVENT - 1;
     /**
      This will be used to initialze the post_header_len, for binlog version
      1 and 3
     */
    static uint8_t server_event_header_length_ver_1_3[]=
    {
      START_V3_HEADER_LEN,
      QUERY_HEADER_MINIMAL_LEN,
      STOP_HEADER_LEN,
      uint8_t(binlog_ver == 1 ? 0 : ROTATE_HEADER_LEN),
      INTVAR_HEADER_LEN,
      LOAD_HEADER_LEN,
      0,/* Unused because the code for Slave log event was removed. (15th Oct. 2010) */
      CREATE_FILE_HEADER_LEN,
      APPEND_BLOCK_HEADER_LEN,
      EXEC_LOAD_HEADER_LEN,
      DELETE_FILE_HEADER_LEN,
      NEW_LOAD_HEADER_LEN,
      RAND_HEADER_LEN,
      USER_VAR_HEADER_LEN
    };
    post_header_len= (uint8_t*)bapi_malloc(number_of_event_types * sizeof(uint8_t)
                                           + BINLOG_CHECKSUM_ALG_DESC_LEN);
    if (post_header_len)
    {
      memcpy(post_header_len, server_event_header_length_ver_1_3, number_of_event_types);
    }
    break;
  }
  default: /* Includes binlog version 2 i.e. 4.0.x x<=1 */
    //TODO: modify the comment regarding is_valid() below
    post_header_len= 0; /* will make is_valid() fail */
    break;
  }
  calc_server_version_split();
}

/**
   This method populates the array server_version_split which is then
   used for lookups to find if the server which
   created this event has some known bug.
*/
void Format_description_event::calc_server_version_split()
{
  do_server_version_split(server_version, server_version_split);
}

/**
   This method is used to find out the version of server that originated
   the current FD instance.
   @return the version of server
*/
unsigned long Format_description_event::get_product_version() const
{
  return version_product(server_version_split);
}

/**
   This method checks the MySQL version to determine whether checksums may be
   present in the events contained in the bainry log.

   @retval TRUE  if the event's version is earlier than one that introduced
                 the replication event checksum.
   @retval FALSE otherwise.
*/
bool Format_description_event::is_version_before_checksum() const
{
  return get_product_version() < checksum_version_product;
}

Start_event_v3::Start_event_v3(const char* buf,
                               const Format_description_event *description_event)
  :Binary_log_event(&buf, description_event->binlog_version,
   description_event->server_version)
{
  buf+= description_event->common_header_len;
  memcpy(&binlog_version, buf + ST_BINLOG_VER_OFFSET, 2);
  binlog_version= le16toh(binlog_version);
  memcpy(server_version, buf + ST_SERVER_VER_OFFSET,
        ST_SERVER_VER_LEN);
  // prevent overrun if log is corrupted on disk
  server_version[ST_SERVER_VER_LEN - 1]= 0;
  created= 0;
  memcpy(&created, buf + ST_CREATED_OFFSET, 4);
  created= le64toh(created);
  dont_set_created= 1;
}

/**
  The problem with this constructor is that the fixed header may have a
  length different from this version, but we don't know this length as we
  have not read the Format_description_log_event which says it, yet. This
  length is in the post-header of the event, but we don't know where the
  post-header starts.

  So this type of event HAS to:
  - either have the header's length at the beginning (in the header, at a
  fixed position which will never be changed), not in the post-header. That
  would make the header be "shifted" compared to other events.
  - or have a header of size LOG_EVENT_MINIMAL_HEADER_LEN (19), in all future
  versions, so that we know for sure.

  I (Guilhem) chose the 2nd solution. Rotate has the same constraint (because
  it is sent before Format_description_log_event).

  The layout of the event data part  in  Format_description_event
  <pre>
        +=====================================+
        | event  | binlog_version   19 : 2    | = 4
        | data   +----------------------------+
        |        | server_version   21 : 50   |
        |        +----------------------------+
        |        | create_timestamp 71 : 4    |
        |        +----------------------------+
        |        | header_length    75 : 1    |
        |        +----------------------------+
        |        | post-header      76 : n    | = array of n bytes, one byte per
        |        | lengths for all            |   event type that the server knows
        |        | event types                |   about
        +=====================================+
  </pre>
*/
Format_description_event::
Format_description_event(const char* buf, unsigned int event_len,
                         const Format_description_event* description_event)
 :Start_event_v3(buf, description_event), event_type_permutation(0)
{
  unsigned long ver_calc;
  buf+= LOG_EVENT_MINIMAL_HEADER_LEN;
  if ((common_header_len= buf[ST_COMMON_HEADER_LEN_OFFSET]) < OLD_HEADER_LEN)
    return; /* sanity check */
  number_of_event_types=
   event_len - (LOG_EVENT_MINIMAL_HEADER_LEN + ST_COMMON_HEADER_LEN_OFFSET + 1);
   post_header_len= (uint8_t*) bapi_memdup((unsigned char*)buf +
                                           ST_COMMON_HEADER_LEN_OFFSET + 1,
                                           number_of_event_types *
                                           sizeof(*post_header_len));
  calc_server_version_split();
  if ((ver_calc= get_product_version()) >= checksum_version_product)
{
    /* the last bytes are the checksum alg desc and value (or value's room) */
    number_of_event_types -= BINLOG_CHECKSUM_ALG_DESC_LEN;
    /*
      FD from the checksum-home version server (ver_calc ==
      checksum_version_product) must have
      number_of_event_types == LOG_EVENT_TYPES.
    */
    assert(ver_calc != checksum_version_product ||
                number_of_event_types == LOG_EVENT_TYPES);
    footer()->checksum_alg= (enum_binlog_checksum_alg)
                                  post_header_len[number_of_event_types];
  }
  else
  {
    footer()->checksum_alg=  BINLOG_CHECKSUM_ALG_UNDEF;
  }

  /*
    In some previous versions, the events were given other event type
    id numbers than in the present version. When replicating from such
    a version, we therefore set up an array that maps those id numbers
    to the id numbers of the present server.
    //TODO: Modify the comment
    If post_header_len is null, it means malloc failed, and subclass method
    is_valid will fail, so there is no need to do anything.

    The trees in which events have wrong id's are:

    mysql-5.1-wl1012.old mysql-5.1-wl2325-5.0-drop6p13-alpha
    mysql-5.1-wl2325-5.0-drop6 mysql-5.1-wl2325-5.0
    mysql-5.1-wl2325-no-dd

    (this was found by grepping for two lines in sequence where the
    first matches "FORMAT_DESCRIPTION_EVENT," and the second matches
    "TABLE_MAP_EVENT," in log_event.h in all trees)

    In these trees, the following server_versions existed since
    TABLE_MAP_EVENT was introduced:
     5.1.1-a_drop5p3   5.1.1-a_drop5p4        5.1.1-alpha
    5.1.2-a_drop5p10  5.1.2-a_drop5p11       5.1.2-a_drop5p12
    5.1.2-a_drop5p13  5.1.2-a_drop5p14       5.1.2-a_drop5p15
    5.1.2-a_drop5p16  5.1.2-a_drop5p16b      5.1.2-a_drop5p16c
    5.1.2-a_drop5p17  5.1.2-a_drop5p4        5.1.2-a_drop5p5
    5.1.2-a_drop5p6   5.1.2-a_drop5p7        5.1.2-a_drop5p8
    5.1.2-a_drop5p9   5.1.3-a_drop5p17       5.1.3-a_drop5p17b
5.1.3-a_drop5p17c 5.1.4-a_drop5p18       5.1.4-a_drop5p19
    5.1.4-a_drop5p20  5.1.4-a_drop6p0        5.1.4-a_drop6p1
    5.1.4-a_drop6p2   5.1.5-a_drop5p20       5.2.0-a_drop6p3
    5.2.0-a_drop6p4   5.2.0-a_drop6p5        5.2.0-a_drop6p6
    5.2.1-a_drop6p10  5.2.1-a_drop6p11       5.2.1-a_drop6p12
    5.2.1-a_drop6p6   5.2.1-a_drop6p7        5.2.1-a_drop6p8
    5.2.2-a_drop6p13  5.2.2-a_drop6p13-alpha 5.2.2-a_drop6p13b
    5.2.2-a_drop6p13c

    (this was found by grepping for "mysql," in all historical
    versions of configure.in in the trees listed above).

    There are 5.1.1-alpha versions that use the new event id's, so we
    do not test that version string.  So replication from 5.1.1-alpha
    with the other event id's to a new version does not work.
    Moreover, we can safely ignore the part after drop[56].  This
    allows us to simplify the big list above to the following regexes:

    5\.1\.[1-5]-a_drop5.*
    5\.1\.4-a_drop6.*
    5\.2\.[0-2]-a_drop6.*

    This is what we test for in the 'if' below.
  */
  if (post_header_len &&
      server_version[0] == '5' && server_version[1] == '.' &&
      server_version[3] == '.' &&
      strncmp(server_version + 5, "-a_drop", 7) == 0 &&
      ((server_version[2] == '1' &&
        server_version[4] >= '1' && server_version[4] <= '5' &&
        server_version[12] == '5') ||
       (server_version[2] == '1' &&
        server_version[4] == '4' &&
        server_version[12] == '6') ||
       (server_version[2] == '2' &&
        server_version[4] >= '0' && server_version[4] <= '2' &&
        server_version[12] == '6')))
  {
    if (number_of_event_types != 22)
    {
      //TODO: modify the below comment
      /* this makes is_valid() return false. */
      bapi_free(post_header_len);
      post_header_len= NULL;
      return;
    }
    static const uint8_t perm[23]=
      {
        UNKNOWN_EVENT, START_EVENT_V3, QUERY_EVENT, STOP_EVENT, ROTATE_EVENT,
        INTVAR_EVENT, LOAD_EVENT, SLAVE_EVENT, CREATE_FILE_EVENT,
        APPEND_BLOCK_EVENT, EXEC_LOAD_EVENT, DELETE_FILE_EVENT,
        NEW_LOAD_EVENT,
        RAND_EVENT, USER_VAR_EVENT,
        FORMAT_DESCRIPTION_EVENT,
        TABLE_MAP_EVENT,
        PRE_GA_WRITE_ROWS_EVENT,
        PRE_GA_UPDATE_ROWS_EVENT,
        PRE_GA_DELETE_ROWS_EVENT,
        XID_EVENT,
        BEGIN_LOAD_QUERY_EVENT,
        EXECUTE_LOAD_QUERY_EVENT,
      };
    event_type_permutation= perm;
    /*
      Since we use (permuted) event id's to index the post_header_len
      array, we need to permute the post_header_len array too.
    */
    uint8_t post_header_len_temp[23];
    for (int i= 1; i < 23; i++)
      post_header_len_temp[perm[i] - 1]= post_header_len[i - 1];
    for (int i= 0; i < 22; i++)
      post_header_len[i] = post_header_len_temp[i];

  }
    return;
}


Format_description_event::~Format_description_event()
{
  if(post_header_len)
    bapi_free((void*)post_header_len);
}
void Binary_log_event::print_event_info(std::ostream& info) {}
void Binary_log_event::print_long_info(std::ostream& info) {}

/********************************************************************
           Rotate_event methods
*********************************************************************/
/**
  The variable part of the Rotate event contains the name of the next binary
  log file,  and the position of the first event in the next binary log file.

  <pre>
  The buffer layout is as follows:
  +-----------------------------------------------------------------------+
  | common_header | post_header | position og the first event | file name |
  +-----------------------------------------------------------------------+
  </pre>

  @param buf Buffer contain event data in the layout specified above
  @param event_len The length of the event written in the log file
  @param description_event FDE used to extract the post header length, which
                           depends on the binlog version
  @param head Header information of the event
*/
Rotate_event::Rotate_event(const char* buf, unsigned int event_len,
                           const Format_description_event *description_event)
: Binary_log_event(&buf, description_event->binlog_version,
                   description_event->server_version), new_log_ident(0),
  flags(DUP_NAME)
{
  // This will ensure that the event_len is what we have at EVENT_LEN_OFFSET
  size_t header_size= description_event->common_header_len;
  size_t post_header_len= description_event->post_header_len[ROTATE_EVENT - 1];
  unsigned int ident_offset;

  if (event_len < header_size)
    return;

  buf += header_size;

  /**
    By default, an event start immediately after the magic bytes in the binary
    log, which is at offset 4. In case if the slave has to rotate to a
    different event instead of the first one, the binary log offset for that
    event is specified in the post header. Else, the position is set to 4.
  */
  if (post_header_len)
  {
    memcpy(&pos, buf + R_POS_OFFSET, 8);
    pos= le64toh(pos);
  }
  else
    pos= 4;

  ident_len= event_len - (header_size + post_header_len);
  ident_offset= post_header_len;
  if (ident_len > FN_REFLEN - 1)
    ident_len= FN_REFLEN - 1;

  new_log_ident= bapi_strndup(buf + ident_offset, ident_len);
}

/**
  This method is used by the binlog_browser to print short and long
  information about the event. Since the body of Stop_event is empty
  the relevant information contains only the timestamp.
  Please note this is different from the print_event_info methods
  used by mysqlbinlog.cc.

  @param std output stream to which the event data is appended.
*/
void Stop_event::print_long_info(std::ostream& info)
{
  info << "Timestamp: " << header()->when.tv_sec;
  this->print_event_info(info);
}

/******************************************************************
            Intvar_event methods
*******************************************************************/
/**
  Constructor receives a packet from the MySQL master or the binary
  log and decodes it to create an Intvar_event.

  @param buf Buffer containing header and event data.
  @param description_event FDE corresponding to the binlog version of the
                               log file being read currently.

  The post header for the event is empty. Buffer layout for the variable
  data part is as follows:
  <pre>
    +--------------------------------+
    | type (4 bytes) | val (8 bytes) |
    +--------------------------------+
  </pre>
*/
Intvar_event::Intvar_event(const char* buf,
                           const Format_description_event* description_event)
: Binary_log_event(&buf, description_event->binlog_version,
                   description_event->server_version)
{
  /*
    TODO: Move the addition by common header len to the constrcutor in
          Binary_log_event when all events are refactored.
  */
  buf+= description_event->common_header_len;
  /* The Post-Header is empty. The Varible Data part begins immediately. */
  buf+= description_event->post_header_len[INTVAR_EVENT - 1];
  type= buf[I_TYPE_OFFSET];
  memcpy(&val, buf + I_VAL_OFFSET, sizeof(val));
  val= le64toh(val);
}

void Unknown_event::print_event_info(std::ostream& info)
{
  info << "Unhandled event";
}

void Unknown_event::print_long_info(std::ostream& info)
{
  info << "Timestamp: " << header()->when.tv_sec;
  this->print_event_info(info);
}


Xid_event::
Xid_event(const char* buf,
          const Format_description_event *description_event)
  :Binary_log_event(&buf, description_event->binlog_version,
                    description_event->server_version)
{
  /* The Post-Header is empty. The Variable Data part begins immediately. */
  buf+= description_event->common_header_len +
        description_event->post_header_len[XID_EVENT-1];
  memcpy((char*) &xid, buf, sizeof(xid));
}

/**
  Written every time a statement uses the RAND() function; precedes other
  events for the statement. Indicates the seed values to use for generating a
  random number with RAND() in the next statement. This is written only before
  a QUERY_EVENT and is not used with row-based logging
*/
Rand_event::Rand_event(const char* buf,
                       const Format_description_event* description_event)
  :Binary_log_event(&buf, description_event->binlog_version,
                    description_event->server_version)
{
  /* The Post-Header is empty. The Variable Data part begins immediately. */
  buf+= description_event->common_header_len +
    description_event->post_header_len[RAND_EVENT - 1];
  memcpy(&seed1, buf + RAND_SEED1_OFFSET, 8);
  seed1= le64toh(seed1);
  memcpy(&seed2, buf + RAND_SEED2_OFFSET, 8);
  seed2= le64toh(seed2);
}

/**
  Written every time a statement uses a user variable, precedes other
  events for the statement. Indicates the value to use for the
  user variable in the next statement. This is written only before a
  QUERY_EVENT and is not used with row-based logging.
*/
User_var_event::
User_var_event(const char* buf, unsigned int event_len,
               const Format_description_event* description_event)
  :Binary_log_event(&buf, description_event->binlog_version,
                    description_event->server_version)
{
  bool error= false;
  const char* buf_start= buf;
  /* The Post-Header is empty. The Variable Data part begins immediately. */
  const char *start= buf;
  buf+= description_event->common_header_len +
    description_event->post_header_len[USER_VAR_EVENT-1];

  memcpy(&name_len, buf, sizeof(name_len));
  name_len= le32toh(name_len);
  name= (char *) buf + UV_NAME_LEN_SIZE;
  /*
    We don't know yet is_null value, so we must assume that name_len
    may have the bigger value possible, is_null= True and there is no
    payload for val, or even that name_len is 0.
  */
  if (!valid_buffer_range<unsigned int>(name_len, buf_start, name,
                                        event_len - UV_VAL_IS_NULL))
  {
    error= true;
    goto err;
  }

  buf+= UV_NAME_LEN_SIZE + name_len;
  is_null= (bool) *buf;
  flags= User_var_event::UNDEF_F;    // defaults to UNDEF_F
  if (is_null)
  {
    type= STRING_TYPE;
    /*
    *my_charset_bin.number= 63, and my_charset_bin is defined in server
    *so replacing it with its value.
    */
    charset_number= 63;
    val_len= 0;
    val= 0;
  }

  else
  {
    if (!valid_buffer_range<unsigned int>(UV_VAL_IS_NULL + UV_VAL_TYPE_SIZE
                                          + UV_CHARSET_NUMBER_SIZE +
                                          UV_VAL_LEN_SIZE, buf_start, buf,
                                          event_len))
    {
      error= true;
      goto err;
    }

    type= (Value_type) buf[UV_VAL_IS_NULL];
     memcpy(&charset_number, buf + UV_VAL_IS_NULL + UV_VAL_TYPE_SIZE,
            sizeof(charset_number));
    charset_number= le32toh(charset_number);
    memcpy(&val_len, (buf + UV_VAL_IS_NULL + UV_VAL_TYPE_SIZE +
           UV_CHARSET_NUMBER_SIZE), sizeof(val_len));
    val_len= le32toh(val_len);
    val= (char *) (buf + UV_VAL_IS_NULL + UV_VAL_TYPE_SIZE +
                   UV_CHARSET_NUMBER_SIZE + UV_VAL_LEN_SIZE);

    if (!valid_buffer_range<unsigned int>(val_len, buf_start, val, event_len))
    {
      error= true;
      goto err;
    }

    /**
      We need to check if this is from an old server
      that did not pack information for flags.
      We do this by checking if there are extra bytes
      after the packed value. If there are we take the
      extra byte and it's value is assumed to contain
      the flags value.

      Old events will not have this extra byte, thence,
      we keep the flags set to UNDEF_F.
    */
  unsigned int bytes_read= ((val + val_len) - start);
#ifndef DBUG_OFF
    bool old_pre_checksum_fd= description_event->is_version_before_checksum();
    assert((bytes_read == header()->data_written -
                 (old_pre_checksum_fd ||
                  (description_event->footer()->checksum_alg ==
                   BINLOG_CHECKSUM_ALG_OFF)) ?

 0 : BINLOG_CHECKSUM_LEN)
                ||
                (bytes_read == header()->data_written -1 -
                 (old_pre_checksum_fd ||
                  (description_event->footer()->checksum_alg ==
                   BINLOG_CHECKSUM_ALG_OFF)) ?
                 0 : BINLOG_CHECKSUM_LEN));
#endif
    if ((header()->data_written - bytes_read) > 0)
    {
      flags= (unsigned int) *(buf + UV_VAL_IS_NULL + UV_VAL_TYPE_SIZE +
                              UV_CHARSET_NUMBER_SIZE + UV_VAL_LEN_SIZE +
                              val_len);
    }
  }
err:
  if (error)
    name= 0;
}

/**
  The ctor of Rows_query_event,
  Here we are copying the exact query executed in RBR, to a
  char array m_rows_query
*/
Rows_query_event::
Rows_query_event(const char *buf, unsigned int event_len,
                 const Format_description_event *descr_event)
 : Ignorable_event(buf, descr_event)
{
  uint8_t const common_header_len=
    descr_event->common_header_len;
  uint8_t const post_header_len=
    descr_event->post_header_len[ROWS_QUERY_LOG_EVENT-1];

  /*
   m_rows_query length is stored using only one byte, but that length is
   ignored and the complete query is read.
  */
  int offset= common_header_len + post_header_len + 1;
  int len= event_len - offset;
  if (!(m_rows_query= (char*) bapi_malloc(len + 1, MEMORY_LOG_EVENT, 16)))
    return;
  bapi_strmake(m_rows_query, buf + offset, len);
}

Rows_query_event::~Rows_query_event()
{
  if(m_rows_query)
     bapi_free(m_rows_query);
}
/**
  ctor of Gtid_event
  Each transaction has a coordinate in the form of a pair:
  GTID = (SID, GNO)
  GTID stands for Global Transaction IDentifier, SID for Source Identifier,
  and GNO for Group Number.

  SID is a 128-bit number that identifies the place where the transaction was
  first committed. SID is normally the SERVER_UUID of a server, but may be
  something different if the transaction was generated by something else than
  a MySQL server. For example, for NDB it identifies the cluster (which may be
  attached to multiple servers).

  GNO is a 64-bit sequence number: 1 for the first transaction committed on SID,
  2 for the second transaction, and so on. No transaction can have GNO 0
*/

Gtid_event::Gtid_event(const char *buffer, uint32_t event_len,
                       const Format_description_event *description_event)
 : Binary_log_event(&buffer, description_event->binlog_version,
                    description_event->server_version)
{
   uint8_t const common_header_len= description_event->common_header_len;

/*
  The layout of the buffer is as follows
   +-------------+-------------+------------+------------+--------------+
   | commit flag | ENCODED SID | ENCODED GNO| G_COMMIT_TS| commit_seq_no|
   +-------------+-------------+------------+------------+--------------+
*/
  char const *ptr_buffer= buffer + common_header_len;

  gtid_info_struct.type= buffer[EVENT_TYPE_OFFSET] == ANONYMOUS_GTID_LOG_EVENT ?
    ANONYMOUS_GROUP : GTID_GROUP;

  commit_flag= *ptr_buffer != 0;
  ptr_buffer+= ENCODED_FLAG_LENGTH;

  memcpy(Uuid_parent_struct.bytes, (const unsigned char*)ptr_buffer,
          Uuid_parent_struct.BYTE_LENGTH);
  ptr_buffer+= ENCODED_SID_LENGTH;

  // SIDNO is only generated if needed, in get_sidno().
  gtid_info_struct.rpl_gtid_sidno= -1;

  memcpy(&(gtid_info_struct.rpl_gtid_gno), ptr_buffer,
         sizeof(gtid_info_struct.rpl_gtid_gno));
  gtid_info_struct.rpl_gtid_gno= le64toh(gtid_info_struct.rpl_gtid_gno);
  ptr_buffer+= ENCODED_GNO_LENGTH;
    /* fetch the commit timestamp */
  if (
      /*Old masters will not have this part, so we should prevent segfaulting */
      (unsigned int)(ptr_buffer - buffer) < event_len &&
      *ptr_buffer == G_COMMIT_TS)
  {
    ptr_buffer++;
    memcpy(&commit_seq_no, ptr_buffer, sizeof(commit_seq_no));
    commit_seq_no= (int64_t)le64toh(commit_seq_no);
    ptr_buffer+= COMMIT_SEQ_LEN;
  }
  else
    /* We let coordinator complain when it sees that we have first
       event and the master has not sent us the commit sequence number
       Also, we can be rest assured that this is an old master, because new
       master would have compained of the missing commit seq no while flushing.*/
    commit_seq_no= SEQ_UNINIT;
  return;
}

/**
  Constructor of Incident_event
  The buffer layout is as follows:
  <pre>
  +-----------------------------------------------------+
  | Incident_number | message_length | Incident_message |
  +-----------------------------------------------------+
  </pre>

  Incident number codes are listed in binlog_evnet.h.
  The only code currently used is INCIDENT_LOST_EVENTS, which indicates that
  there may be lost events (a "gap") in the replication stream that requires
  databases to be resynchronized.
*/
Incident_event::Incident_event(const char *buf, unsigned int event_len,
                               const Format_description_event *descr_event)
: Binary_log_event(&buf, descr_event->binlog_version,
                   descr_event->server_version)
{
  uint8_t const common_header_len= descr_event->common_header_len;
  uint8_t const post_header_len= descr_event->post_header_len[INCIDENT_EVENT-1];

  message= NULL;
  message_length= 0;
  uint16_t incident_number;
  memcpy(&incident_number, buf + common_header_len, sizeof(incident_number));
  incident_number= le16toh(incident_number);
  if (incident_number >= INCIDENT_COUNT ||
      incident_number <= INCIDENT_NONE)
  {
    /*
      If the incident is not recognized, this binlog event is
      invalid.
    */
    incident= INCIDENT_NONE;

  }
  incident= static_cast<enum_incident>(incident_number);
  char const *ptr= buf + common_header_len + post_header_len;
  char const *const str_end= buf + event_len;
  uint8_t len= 0;                   // Assignment to keep compiler happy
  const char *str= NULL;          // Assignment to keep compiler happy
  read_str_at_most_255_bytes(&ptr, str_end, &str, &len);
  if (!(message= (char*) bapi_malloc(len + 1, MEMORY_LOG_EVENT, 16)))
  {
    /* Mark this event invalid */
    incident= INCIDENT_NONE;
    return;
  }

  bapi_strmake(message, str, len);
  message_length= len;
  return;
}

/**
  Constructor of Previous_gtid_event
  Decodes the gtid_executed in the last binlog file
*/

Previous_gtids_event::
Previous_gtids_event(const char *buffer, unsigned int event_len,
                     const Format_description_event *description_event)
: Binary_log_event(&buffer, description_event->binlog_version,
                     description_event->server_version)
{
  uint8_t const common_header_len= description_event->common_header_len;
  uint8_t const post_header_len=
    description_event->post_header_len[PREVIOUS_GTIDS_LOG_EVENT - 1];

  buf= (const unsigned char *)buffer + common_header_len + post_header_len;
  buf_size= event_len - common_header_len - post_header_len;
  return;
}
/******************************************************************************
                     Query_event methods
******************************************************************************/
/**
  The simplest constructor that could possibly work.  This is used for
  creating static objects that have a special meaning and are invisible
  to the log.
*/
Query_event::Query_event(Log_event_type type_arg)
: Binary_log_event(type_arg),
  m_user(""), m_host("")
{
}

/**
  The constructor used by MySQL master to create a query event, to be
  written to the binary log.
*/
Query_event::Query_event(const char* query_arg, const char* catalog_arg,
                         const char* db_arg, uint32_t query_length,
                         unsigned long thread_id_arg,
                         unsigned long long sql_mode_arg,
                         unsigned long auto_increment_increment_arg,
                         unsigned long auto_increment_offset_arg,
                         unsigned int number,
                         unsigned long long table_map_for_update_arg,
                         int errcode,
                         unsigned int db_arg_len, unsigned int catalog_arg_len)
: Binary_log_event(QUERY_EVENT),
  m_user(""), m_host(""), m_catalog(""),
  m_db(""), m_query(""),
  thread_id(thread_id_arg), db_len(0), error_code(errcode),
  status_vars_len(0), q_len(query_length),
  flags2_inited(1), sql_mode_inited(1), charset_inited(1),
  sql_mode(sql_mode_arg),
  auto_increment_increment(auto_increment_increment_arg),
  auto_increment_offset(auto_increment_offset_arg),
  time_zone_len(0), lc_time_names_number(number),
  charset_database_number(0),
  table_map_for_update(table_map_for_update_arg),
  master_data_written(0), mts_accessed_dbs(0)
{
  if (db_arg)
    m_db.append(db_arg, db_arg_len);
  if (query_arg)
    m_query.append(query_arg, query_length);
  if (catalog_arg)
    m_catalog.append(catalog_arg, catalog_arg_len);
}

/**
  Utility function for the Query_event constructor.
  The function copies n bytes from the source string and moves the
  destination pointer by the number of bytes copied.

  @param dst Pointer to the buffer into which the string is to be copied
  @param src Source string
  @param len The number of bytes to be copied
*/
static void copy_str_and_move(Log_event_header::Byte **dst,
                              const std::string &src,
                              unsigned int len)
{
  memcpy(*dst, src.c_str(), len);
  (*dst)+= len;
  *(*dst)++= 0;
}

/**
  utility function to return the string representation of the status variable
  used in the Query_event.

  @param Integer value representing the status variable code

  @return String representation of the code
*/
char const *
Query_event::code_name(int code)
{
  static char buf[255];
  switch (code) {
  case Q_FLAGS2_CODE: return "Q_FLAGS2_CODE";
  case Q_SQL_MODE_CODE: return "Q_SQL_MODE_CODE";
  case Q_CATALOG_CODE: return "Q_CATALOG_CODE";
  case Q_AUTO_INCREMENT: return "Q_AUTO_INCREMENT";
  case Q_CHARSET_CODE: return "Q_CHARSET_CODE";
  case Q_TIME_ZONE_CODE: return "Q_TIME_ZONE_CODE";
  case Q_CATALOG_NZ_CODE: return "Q_CATALOG_NZ_CODE";
  case Q_LC_TIME_NAMES_CODE: return "Q_LC_TIME_NAMES_CODE";
  case Q_CHARSET_DATABASE_CODE: return "Q_CHARSET_DATABASE_CODE";
  case Q_TABLE_MAP_FOR_UPDATE_CODE: return "Q_TABLE_MAP_FOR_UPDATE_CODE";
  case Q_MASTER_DATA_WRITTEN_CODE: return "Q_MASTER_DATA_WRITTEN_CODE";
  case Q_UPDATED_DB_NAMES: return "Q_UPDATED_DB_NAMES";
  case Q_MICROSECONDS: return "Q_MICROSECONDS";
  case Q_COMMIT_TS: return "Q_COMMIT_TS";
  }
  sprintf(buf, "CODE#%d", code);
  return buf;
}

/**
   Macro to check that there is enough space to read from memory.

   @param PTR Pointer to memory
   @param END End of memory
   @param CNT Number of bytes that should be read.
*/
#define CHECK_SPACE(PTR,END,CNT)                      \
  do {                                                \
    assert((PTR) + (CNT) <= (END));              \
    if ((PTR) + (CNT) > (END)) {                      \
      m_query= "";                                       \
      return;                               \
    }                                                 \
  } while (0)


/**
  The constructor receives a packet from the MySQL master or the binary
  log and decodes it to create a Query event.

  @param buf                Containing the event header and data
  @param even_len           The length upto ehich buf contains Query event data
  @param description_event  FDE specific to the binlog version

  @param event_type         Required to determine whether the event type is
                            QUERY_EVENT or EXECUTE_LOAD_QUERY_EVENT
*/
Query_event::Query_event(const char* buf, unsigned int event_len,
                         const Format_description_event *description_event,
                         Log_event_type event_type)
: Binary_log_event(&buf, description_event->binlog_version,
                   description_event->server_version),
  m_user(""), m_host(""),m_db(""), m_query(""),
  db_len(0), status_vars_len(0), q_len(0),
  flags2_inited(0), sql_mode_inited(0), charset_inited(0),
  auto_increment_increment(1), auto_increment_offset(1),
  time_zone_len(0), catalog_len(0), lc_time_names_number(0),
  charset_database_number(0), table_map_for_update(0), master_data_written(0),
  mts_accessed_dbs(OVER_MAX_DBS_IN_EVENT_MTS), commit_seq_no(SEQ_UNINIT)
{
  uint32_t tmp;
  uint8_t common_header_len, post_header_len;
  Log_event_header::Byte *start;
  const Log_event_header::Byte *end;

  query_data_written= 0;

  common_header_len= description_event->common_header_len;
  post_header_len= description_event->post_header_len[event_type - 1];

  /*
    We test if the event's length is sensible, and if so we compute data_len.
    We cannot rely on QUERY_HEADER_LEN here as it would not be format-tolerant.
    We use QUERY_HEADER_MINIMAL_LEN which is the same for 3.23, 4.0 & 5.0.
  */
  if (event_len < (unsigned int)(common_header_len + post_header_len))
    return;
  data_len= event_len - (common_header_len + post_header_len);
  buf+= common_header_len;

  memcpy(&thread_id, buf + Q_THREAD_ID_OFFSET, sizeof(thread_id));
  thread_id= le32toh(thread_id);
  memcpy(&query_exec_time, buf + Q_EXEC_TIME_OFFSET, sizeof(query_exec_time));
  query_exec_time= le32toh(query_exec_time);

  db_len= (unsigned int)buf[Q_DB_LEN_OFFSET];
   // TODO: add a check of all *_len vars
  memcpy(&error_code, buf + Q_ERR_CODE_OFFSET, sizeof(error_code));
  error_code= le16toh(error_code);

  /*
    5.0 format starts here.
    Depending on the format, we may or not have affected/warnings etc
    The remnent post-header to be parsed has length:
  */
  tmp= post_header_len - QUERY_HEADER_MINIMAL_LEN;
  if (tmp)
  {
    memcpy(&status_vars_len, buf + Q_STATUS_VARS_LEN_OFFSET,
           sizeof(status_vars_len));
    status_vars_len= le16toh(status_vars_len);
    /*
      Check if status variable length is corrupt and will lead to very
      wrong data. We could be even more strict and require data_len to
      be even bigger, but this will suffice to catch most corruption
      errors that can lead to a crash.
    */
    if (status_vars_len >
        std::min<unsigned long>(data_len, MAX_SIZE_LOG_EVENT_STATUS))
    {
      m_query= "";
      return;
    }
    data_len-= status_vars_len;
    tmp-= 2;
  }
  else
  {
    /*
      server version < 5.0 / binlog_version < 4 master's event is
      relay-logged with storing the original size of the event in
      Q_MASTER_DATA_WRITTEN_CODE status variable.
      The size is to be restored at reading Q_MASTER_DATA_WRITTEN_CODE-marked
      event from the relay log.
    */
    assert(description_event->binlog_version < 4);
    master_data_written= header()->data_written;
  }
  /*
    We have parsed everything we know in the post header for QUERY_EVENT,
    the rest of post header is either comes from older version MySQL or
    dedicated to derived events (e.g. Execute_load_query...)
  */

  /* variable-part: the status vars; only in MySQL 5.0  */
  start= (Log_event_header::Byte*) (buf + post_header_len);
  end= (const Log_event_header::Byte*) (start + status_vars_len);
  for (const Log_event_header::Byte* pos= start; pos < end;)
  {
    switch (*pos++) {
    case Q_FLAGS2_CODE:
      CHECK_SPACE(pos, end, 4);
      flags2_inited= 1;
      memcpy(&flags2, pos, sizeof(flags2));
      flags2= le32toh(flags2);
      pos+= 4;
      break;
    case Q_SQL_MODE_CODE:
    {
      CHECK_SPACE(pos, end, 8);
      sql_mode_inited= 1;
      memcpy(&sql_mode, pos, sizeof(sql_mode));
      sql_mode= le64toh(sql_mode);
      pos+= 8;
      break;
    }
    case Q_CATALOG_NZ_CODE:
      if ((catalog_len= *pos))
        m_catalog= std::string((const char*) (pos + 1), catalog_len);
      CHECK_SPACE(pos, end, catalog_len + 1);
      pos+= catalog_len + 1;
      break;
    case Q_AUTO_INCREMENT:
      CHECK_SPACE(pos, end, 4);
      memcpy(&auto_increment_increment, pos, sizeof(auto_increment_increment));
      auto_increment_increment= le16toh(auto_increment_increment);
      memcpy(&auto_increment_offset, pos + 2, sizeof(auto_increment_offset));
      auto_increment_offset= le16toh(auto_increment_offset);
      pos+= 4;
      break;
    case Q_CHARSET_CODE:
    {
      CHECK_SPACE(pos, end, 6);
      charset_inited= 1;
      memcpy(charset, pos, 6);
      pos+= 6;
      break;
    }
    case Q_TIME_ZONE_CODE:
    {
      if ((time_zone_len= *pos))
        m_time_zone_str= std::string((const char*) (pos + 1), time_zone_len);
      pos+= time_zone_len + 1;
      break;
    }
    case Q_CATALOG_CODE: /* for 5.0.x where 0<=x<=3 masters */
      CHECK_SPACE(pos, end, 1);
      if ((catalog_len= *pos))
        m_catalog= std::string((const char*) (pos+1), catalog_len);
      CHECK_SPACE(pos, end, catalog_len + 2);
      pos+= catalog_len + 2; // leap over end 0
      break;
    case Q_LC_TIME_NAMES_CODE:
      CHECK_SPACE(pos, end, 2);
      memcpy(&lc_time_names_number, pos, sizeof(lc_time_names_number));
      lc_time_names_number= le16toh(lc_time_names_number);
      pos+= 2;
      break;
    case Q_CHARSET_DATABASE_CODE:
      CHECK_SPACE(pos, end, 2);
      memcpy(&charset_database_number, pos, sizeof(lc_time_names_number));
      charset_database_number= le16toh(charset_database_number);
      pos+= 2;
      break;
    case Q_TABLE_MAP_FOR_UPDATE_CODE:
      CHECK_SPACE(pos, end, 8);
      memcpy(&table_map_for_update, pos, sizeof(table_map_for_update));
      table_map_for_update= le64toh(table_map_for_update);
      pos+= 8;
      break;
    case Q_MASTER_DATA_WRITTEN_CODE:
      CHECK_SPACE(pos, end, 4);
      memcpy(&master_data_written, pos, sizeof(master_data_written));
      master_data_written= le32toh(master_data_written);
      header()->data_written= master_data_written;
      pos+= 4;
      break;
    case Q_MICROSECONDS:
    {
      CHECK_SPACE(pos, end, 3);
      uint32_t temp_usec= 0;
      memcpy(&temp_usec, pos, 3);
      header()->when.tv_usec= le32toh(temp_usec);
      pos+= 3;
      break;
    }
    case Q_INVOKER:
    {
      CHECK_SPACE(pos, end, 1);
      size_t user_len= *pos++;
      CHECK_SPACE(pos, end, user_len);
      m_user= std::string((const char *)pos, user_len);
      pos+= user_len;

      CHECK_SPACE(pos, end, 1);
      size_t host_len= *pos++;
      CHECK_SPACE(pos, end, host_len);
      m_host= std::string((const char *)pos, host_len);
      pos+= host_len;
      break;
    }
    case Q_UPDATED_DB_NAMES:
    {
      unsigned char i= 0;
      CHECK_SPACE(pos, end, 1);
      mts_accessed_dbs= *pos++;
      /*
         Notice, the following check is positive also in case of
         the master's MAX_DBS_IN_EVENT_MTS > the slave's one and the event
         contains e.g the master's MAX_DBS_IN_EVENT_MTS db:s.
      */
      if (mts_accessed_dbs > MAX_DBS_IN_EVENT_MTS)
      {
        mts_accessed_dbs= OVER_MAX_DBS_IN_EVENT_MTS;
        break;
      }

      assert(mts_accessed_dbs != 0);

      for (i= 0; i < mts_accessed_dbs && pos < start + status_vars_len; i++)
      {
        #ifndef DBUG_OFF
        /*
          This is specific to mysql test run on the server
          for the keyword "query_log_event_mts_corrupt_db_names"
        */
        if (binary_log_debug::debug_query_mts_corrupt_db_names)
        {
          if (mts_accessed_dbs == 2)
          {
            assert(pos[sizeof("d?") - 1] == 0);
            ((char*) pos)[sizeof("d?") - 1]= 'a';
           }
        }
        #endif
        strncpy(mts_accessed_db_names[i], (char*) pos,
                std::min<ulong>(NAME_LEN, start + status_vars_len - pos));
        mts_accessed_db_names[i][NAME_LEN - 1]= 0;
        pos+= 1 + strlen((const char*) pos);
      }
      if (i != mts_accessed_dbs || pos > start + status_vars_len)
        return;
      break;
    }
    case Q_COMMIT_TS:
      CHECK_SPACE(pos, end, COMMIT_SEQ_LEN);
      commit_seq_no =0;
      memcpy(&commit_seq_no, pos, 8);
      commit_seq_no= le64toh(commit_seq_no);
      pos+= COMMIT_SEQ_LEN;
      break;

    default:
      /* That's why you must write status vars in growing order of code */
      pos= (const unsigned char*) end;         // Break loop
    }
  }
  if (catalog_len)                             // If catalog is given
    query_data_written+= catalog_len + 1;
  if (time_zone_len)
    query_data_written+= time_zone_len + 1;
  if (m_user.length() > 0)
    query_data_written+= m_user.length() + 1;
  if (m_host.length() > 0)
    query_data_written+= m_host.length() + 1;

  /*
    if time_zone_len or catalog_len are 0, then time_zone and catalog
    are uninitialized at this point.  shouldn't they point to the
    zero-length null-terminated strings we allocated space for in the
    my_alloc call above? /sven
  */

  /* A 2nd variable part; this is common to all versions */
  query_data_written+= data_len + 1;
  m_db= std::string((const char *)end, db_len);
  q_len= data_len - db_len -1;
  m_query= std::string((const char *)(end + db_len + 1), q_len);
  return;
}

/**
  Layout for the data buffer is as follows
  <pre>
  +--------+-----------+------+------+---------+----+-------+----+
  | catlog | time_zone | user | host | db name | \0 | Query | \0 |
  +--------+-----------+------+------+---------+----+-------+----+
  </pre>
*/
int Query_event::fill_data_buf(Log_event_header::Byte* buf)
{
  if (!buf)
    return 0;
  unsigned char* start= buf;
  /*
    Note: catalog_len is one less than "catalog.length()"
    if Q_CATALOG flag is set
   */
  if (catalog_len)                                  // If catalog is given
    /*
      This covers both the cases, where the catalog_nz flag is set of unset.
      The end 0 will be a part of the string catalog in the second case,
      hence using catalog.length() instead of catalog_len makes the flags
      catalog_nz redundant.
     */
    copy_str_and_move(&start, m_catalog, catalog_len);
  if (m_time_zone_str.length() > 0)
    copy_str_and_move(&start, m_time_zone_str, m_time_zone_str.length());
  if (m_user.length() > 0)
    copy_str_and_move(&start, m_user, m_user.length());
  if (m_host.length() > 0)
    copy_str_and_move(&start, m_host, m_host.length());
  if (data_len)
  {
    copy_str_and_move(&start, m_db, m_db.length());
    copy_str_and_move(&start, m_query, m_query.length());
  }
  return 1;
}


void Query_event::print_event_info(std::ostream& info)
{
  if (strcmp(m_query.c_str(), "BEGIN") != 0 &&
      strcmp(m_query.c_str(), "COMMIT") != 0)
  {
    info << "use `" << m_db << "`; ";
  }
  info << m_query;
}

void Query_event::print_long_info(std::ostream& info)
{
  info << "Timestamp: " << header()->when.tv_sec;
  info << "\tThread id: " << (int)thread_id;
  info << "\tExec time: " << (int)query_exec_time;
  info << "\nDatabase: " << m_db;
  info << "\tQuery: ";
  this->print_event_info(info);
}


Heartbeat_event::Heartbeat_event(const char* buf, unsigned int event_len,
                                 const Format_description_event*
                                 description_event)
: Binary_log_event(&buf, description_event->binlog_version,
                   description_event->server_version)
{
  unsigned char header_size= description_event->common_header_len;
  ident_len= event_len - header_size;
  if (ident_len > FN_REFLEN - 1)
    ident_len= FN_REFLEN - 1;
  log_ident= buf + header_size;
}


void Rotate_event::print_event_info(std::ostream& info)
{
  info << "Binlog Position: " << pos;
  info << ", Log name: " << new_log_ident;
}

void Rotate_event::print_long_info(std::ostream& info)
{
  info << "Timestamp: " << header()->when.tv_sec;
  info << "\t";
  this->print_event_info(info);
}

void Format_description_event::print_event_info(std::ostream& info)
{
  info << "Server ver: " << server_version;
  info << ", Binlog ver: " << binlog_version;
}

void Format_description_event::print_long_info(std::ostream& info)
{
  this->print_event_info(info);
  info << "\nCreated timestamp: " << created;
  info << "\tCommon Header Length: " << common_header_len;
  info << "\nPost header length for events: \n";
}

void User_var_event::print_event_info(std::ostream& info)
{
  info << "@`" << name << "`=";
  if(type == STRING_TYPE)
    info  << val;
  else
    info << "<Binary encoded value>";
  //TODO: value is binary encoded, requires decoding
}

void User_var_event::print_long_info(std::ostream& info)
{
  info << "Timestamp: " << header()->when.tv_sec;
  info << "\tType: "
       << get_value_type_string(static_cast<Value_type>(type));
  info << "\n";
  this->print_event_info(info);
}



void Intvar_event::print_event_info(std::ostream& info)
{
  info << get_var_type_string();
  info << "\tValue: " << val;
}

void Intvar_event::print_long_info(std::ostream& info)
{
  info << "Timestamp: " << header()->when.tv_sec;
  info << "\t";
  this->print_event_info(info);
}

void Incident_event::print_event_info(std::ostream& info)
{
 //TODO: modify this method with the new members aadded
 // info << m_message;
}

void Incident_event::print_long_info(std::ostream& info)
{
  this->print_event_info(info);
}

void Xid_event::print_event_info(std::ostream& info)
{
  //TODO: Write process_event function for Xid events
  info << "Xid ID=" << xid;
}

void Xid_event::print_long_info(std::ostream& info)
{
  info << "Timestamp: " << header()->when.tv_sec;
  info << "\t";
  this->print_event_info(info);
}

void Rand_event::print_event_info(std::ostream& info)
{
  info << " SEED1 is " << seed1;
  info << " SEED2 is " << seed2;
}
void Rand_event::print_long_info(std::ostream& info)
{
  info << "Timestamp: " << header()->when.tv_sec;
  info << "\t";
  this->print_event_info(info);
}
} // end namespace binary_log
