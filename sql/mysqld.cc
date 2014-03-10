/* Copyright (c) 2000, 2014, Oracle and/or its affiliates. All rights reserved.

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

#include "my_global.h"                          /* NO_EMBEDDED_ACCESS_CHECKS */

#include <vector>
#include <algorithm>
#include <functional>
#include <list>
#include <set>
#include <string>

#include "sql_priv.h"
#include "unireg.h"
#include <signal.h>
#include "sql_parse.h"    // test_if_data_home_dir
#include "sql_cache.h"    // query_cache, query_cache_*
#include "sql_locale.h"   // MY_LOCALES, my_locales, my_locale_by_name
#include "sql_show.h"     // free_status_vars, add_status_vars,
                          // reset_status_vars
#include "strfunc.h"      // find_set_from_flags
#include "parse_file.h"   // File_parser_dummy_hook
#include "sql_db.h"       // my_dboptions_cache_free
                          // my_dboptions_cache_init
#include "sql_table.h"    // release_ddl_log, execute_ddl_log_recovery
#include "sql_connect.h"  // free_max_user_conn, init_max_user_conn,
                          // handle_one_connection
#include "sql_time.h"     // known_date_time_formats,
                          // get_date_time_format_str
#include "tztime.h"       // my_tz_free, my_tz_init, my_tz_SYSTEM
#include "hostname.h"     // hostname_cache_free, hostname_cache_init
#include "auth_common.h"  // set_default_auth_plugin
                          // acl_free, acl_init
                          // grant_free, grant_init
#include "sql_base.h"     // table_def_free, table_def_init,
                          // Table_cache,
                          // cached_table_definitions
#include "sql_test.h"     // mysql_print_status
#include "item_create.h"  // item_create_cleanup, item_create_init
#include "sql_servers.h"  // servers_free, servers_init
#include "init.h"         // unireg_init
#include "derror.h"       // init_errmessage
#include "derror.h"       // init_errmessage
#include "des_key_file.h" // load_des_key_file
#include "sql_manager.h"  // stop_handle_manager, start_handle_manager
#include "bootstrap.h"    // bootstrap
#include <m_ctype.h>
#include <my_dir.h>
#include <my_bit.h>
#include "rpl_gtid.h"
#include "rpl_slave.h"
#include "rpl_master.h"
#include "rpl_mi.h"
#include "rpl_filter.h"
#include <sql_common.h>
#include <my_stacktrace.h>
#include "mysqld_suffix.h"
#include "mysys_err.h"
#include "events.h"
#include "sql_audit.h"
#include "probes_mysql.h"
#include "debug_sync.h"
#include "sql_callback.h"
#include "opt_trace_context.h"

#include "mysqld.h"
#include "my_default.h"

#ifdef WITH_PERFSCHEMA_STORAGE_ENGINE
#include "../storage/perfschema/pfs_server.h"
#include <pfs_idle_provider.h>
#endif /* WITH_PERFSCHEMA_STORAGE_ENGINE */

#include <mysql/psi/mysql_idle.h>
#include <mysql/psi/mysql_socket.h>
#include <mysql/psi/mysql_memory.h>
#include <mysql/psi/mysql_statement.h>

#include "mysql_com_server.h"

#include "keycaches.h"
#include "../storage/myisam/ha_myisam.h"
#include "set_var.h"

#include "sys_vars_shared.h"

#include "rpl_injector.h"

#include "rpl_handler.h"

#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include <thr_alarm.h>
#include <ft_global.h>
#include <errmsg.h>
#include "sp_rcontext.h"
#include "sp_cache.h"
#include "sql_reload.h"  // reload_acl_and_cache
#include "sp_head.h"  // init_sp_psi_keys
#include "event_data_objects.h" //init_scheduler_psi_keys

#include "my_timer.h"    // my_timer_init, my_timer_deinit

#ifdef HAVE_POLL_H
#include <poll.h>
#endif

#ifdef HAVE_FESETROUND
#include <fenv.h>
#endif
#include "table_cache.h"                // table_cache_manager
#include "connection_acceptor.h"        // Connection_acceptor
#include "connection_handler_impl.h"    // *_connection_handler
#include "connection_handler_manager.h" // Connection_handler_manager
#include "socket_connection.h"          // Mysqld_socket_listener
#include "mysqld_thd_manager.h"         // Global_THD_manager

using std::min;
using std::max;
using std::vector;

#define mysqld_charset &my_charset_latin1

#include <errno.h>
#include <sys/stat.h>
#ifndef __GNU_LIBRARY__
#define __GNU_LIBRARY__       // Skip warnings in getopt.h
#endif
#include <my_getopt.h>
#ifdef HAVE_SYSENT_H
#include <sysent.h>
#endif
#ifdef HAVE_PWD_H
#include <pwd.h>        // For getpwent
#endif
#ifdef HAVE_GRP_H
#include <grp.h>
#endif
#include <my_net.h>

#if !defined(_WIN32)
#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif
#ifdef HAVE_SELECT_H
#include <select.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#include <sys/utsname.h>
#endif /* _WIN32 */

#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#ifdef _WIN32
#include <crtdbg.h>
#endif

#ifdef _WIN32
#include "named_pipe.h"
#include "named_pipe_connection.h"
#include "shared_memory_connection.h"
#endif

#ifdef HAVE_SOLARIS_LARGE_PAGES
#include <sys/mman.h>
#if defined(__sun__) && defined(__GNUC__) && defined(__cplusplus) \
    && defined(_XOPEN_SOURCE)
extern "C" int getpagesizes(size_t *, int);
extern "C" int getpagesizes2(size_t *, int);
extern "C" int memcntl(caddr_t, size_t, int, caddr_t, int, int);
#endif /* __sun__ ... */
#endif /* HAVE_SOLARIS_LARGE_PAGES */

#if defined(__FreeBSD__) && defined(HAVE_IEEEFP_H) && !defined(HAVE_FEDISABLEEXCEPT)
#include <ieeefp.h>
#ifdef HAVE_FP_EXCEPT       // Fix type conflict
typedef fp_except fp_except_t;
#endif
#endif /* __FreeBSD__ && HAVE_IEEEFP_H && !HAVE_FEDISABLEEXCEPT */
#ifdef HAVE_FPU_CONTROL_H
#include <fpu_control.h>
#endif
#if defined(__i386__) && !defined(HAVE_FPU_CONTROL_H)
# define fpu_control_t unsigned int
# define _FPU_EXTENDED 0x300
# define _FPU_DOUBLE 0x200
# if defined(__GNUC__) || (defined(__SUNPRO_CC) && __SUNPRO_CC >= 0x590)
#  define _FPU_GETCW(cw) asm volatile ("fnstcw %0" : "=m" (*&cw))
#  define _FPU_SETCW(cw) asm volatile ("fldcw %0" : : "m" (*&cw))
# else
#  define _FPU_GETCW(cw) (cw= 0)
#  define _FPU_SETCW(cw)
# endif
#endif

inline void setup_fpu()
{
#if defined(__FreeBSD__) && defined(HAVE_IEEEFP_H) && !defined(HAVE_FEDISABLEEXCEPT)
  /* We can't handle floating point exceptions with threads, so disable
     this on freebsd
     Don't fall for overflow, underflow,divide-by-zero or loss of precision.
     fpsetmask() is deprecated in favor of fedisableexcept() in C99.
  */
#if defined(FP_X_DNML)
  fpsetmask(~(FP_X_INV | FP_X_DNML | FP_X_OFL | FP_X_UFL | FP_X_DZ |
        FP_X_IMP));
#else
  fpsetmask(~(FP_X_INV |             FP_X_OFL | FP_X_UFL | FP_X_DZ |
              FP_X_IMP));
#endif /* FP_X_DNML */
#endif /* __FreeBSD__ && HAVE_IEEEFP_H && !HAVE_FEDISABLEEXCEPT */

#ifdef HAVE_FEDISABLEEXCEPT
  fedisableexcept(FE_ALL_EXCEPT);
#endif

#ifdef HAVE_FESETROUND
    /* Set FPU rounding mode to "round-to-nearest" */
  fesetround(FE_TONEAREST);
#endif /* HAVE_FESETROUND */

  /*
    x86 (32-bit) requires FPU precision to be explicitly set to 64 bit
    (double precision) for portable results of floating point operations.
    However, there is no need to do so if compiler is using SSE2 for floating
    point, double values will be stored and processed in 64 bits anyway.
  */
#if defined(__i386__) && !defined(__SSE2_MATH__)
#if defined(_WIN32)
#if !defined(_WIN64)
  _control87(_PC_53, MCW_PC);
#endif /* !_WIN64 */
#else /* !_WIN32 */
  fpu_control_t cw;
  _FPU_GETCW(cw);
  cw= (cw & ~_FPU_EXTENDED) | _FPU_DOUBLE;
  _FPU_SETCW(cw);
#endif /* _WIN32 && */
#endif /* __i386__ */

}

#define MYSQL_KILL_SIGNAL SIGTERM

#ifdef SOLARIS
extern "C" int gethostname(char *name, int namelen);
#endif

#ifndef EMBEDDED_LIBRARY
extern "C" void handle_fatal_signal(int sig);
#endif

/* Constants */

#include <welcome_copyright_notice.h> // ORACLE_WELCOME_COPYRIGHT_NOTICE

const char *show_comp_option_name[]= {"YES", "NO", "DISABLED"};

static const char *tc_heuristic_recover_names[]=
{
  "COMMIT", "ROLLBACK", NullS
};
static TYPELIB tc_heuristic_recover_typelib=
{
  array_elements(tc_heuristic_recover_names)-1,"",
  tc_heuristic_recover_names, NULL
};

const char *first_keyword= "first", *binary_keyword= "BINARY";
const char *my_localhost= "localhost";

bool opt_large_files= sizeof(my_off_t) > 4;
static my_bool opt_autocommit; ///< for --autocommit command-line option

/*
  Used with --help for detailed option
*/
static my_bool opt_help= 0, opt_verbose= 0;

arg_cmp_func Arg_comparator::comparator_matrix[5][2] =
{{&Arg_comparator::compare_string,     &Arg_comparator::compare_e_string},
 {&Arg_comparator::compare_real,       &Arg_comparator::compare_e_real},
 {&Arg_comparator::compare_int_signed, &Arg_comparator::compare_e_int},
 {&Arg_comparator::compare_row,        &Arg_comparator::compare_e_row},
 {&Arg_comparator::compare_decimal,    &Arg_comparator::compare_e_decimal}};

#ifdef HAVE_PSI_INTERFACE
#ifndef EMBEDDED_LIBRARY
#if defined(_WIN32)
static PSI_thread_key key_thread_handle_con_namedpipes;
static PSI_thread_key key_thread_handle_con_sharedmem;
static PSI_thread_key key_thread_handle_con_sockets;
static PSI_mutex_key key_LOCK_handler_count;
static PSI_cond_key key_COND_handler_count;
static PSI_thread_key key_thread_handle_shutdown;
#else
static PSI_mutex_key key_LOCK_socket_listener_active;
static PSI_cond_key key_COND_socket_listener_active;
static PSI_mutex_key key_LOCK_start_signal_handler;
static PSI_cond_key key_COND_start_signal_handler;
#endif // _WIN32
#endif // !EMBEDDED_LIBRARY

#if defined (HAVE_OPENSSL) && !defined(HAVE_YASSL)
static PSI_rwlock_key key_rwlock_openssl;
#endif
#endif /* HAVE_PSI_INTERFACE */

/**
  Statement instrumentation key for replication.
*/
#ifdef HAVE_PSI_STATEMENT_INTERFACE
PSI_statement_info stmt_info_rpl;
#endif

/* the default log output is log tables */
static bool lower_case_table_names_used= 0;
#if !defined(_WIN32) && !defined(EMBEDDED_LIBRARY)
static bool socket_listener_active= false;
#endif
static my_bool opt_debugging= 0, opt_external_locking= 0, opt_console= 0;
static my_bool opt_short_log_format= 0;
static char *mysqld_user, *mysqld_chroot;
static char *default_character_set_name;
static char *character_set_filesystem_name;
static char *lc_messages;
static char *lc_time_names_name;
char *my_bind_addr_str;
static char *default_collation_name;
char *default_storage_engine;
char *default_tmp_storage_engine;
static char compiled_default_collation_name[]= MYSQL_DEFAULT_COLLATION_NAME;
static bool binlog_format_used= false;

LEX_STRING opt_init_connect, opt_init_slave;

/* Global variables */

bool opt_bin_log, opt_ignore_builtin_innodb= 0;
bool opt_general_log, opt_slow_log, opt_general_log_raw;
ulonglong log_output_options;
my_bool opt_log_queries_not_using_indexes= 0;
ulong opt_log_throttle_queries_not_using_indexes= 0;
bool opt_error_log= IF_WIN(1,0);
bool opt_disable_networking=0, opt_skip_show_db=0;
bool opt_skip_name_resolve=0;
my_bool opt_character_set_client_handshake= 1;
bool server_id_supplied = false;
bool opt_endinfo, using_udf_functions;
my_bool locked_in_memory;
bool opt_using_transactions;
bool volatile abort_loop;
ulong log_warnings;
#if defined(_WIN32)
/*
  Thread handle of shutdown event handler thread.
  It is used as argument during thread join.
*/
HANDLE shutdown_thr_handle= NULL;
#endif
uint host_cache_size;
ulong log_error_verbosity= 3; // have a non-zero value during early start-up
#if defined(_WIN32) && !defined(EMBEDDED_LIBRARY)
ulong slow_start_timeout;
#endif

my_bool opt_bootstrap= 0;

/**
   @brief 'grant_option' is used to indicate if privileges needs
   to be checked, in which case the lock, LOCK_grant, is used
   to protect access to the grant table.
   @note This flag is dropped in 5.1
   @see grant_init()
 */
bool volatile grant_option;

my_bool opt_skip_slave_start = 0; ///< If set, slave is not autostarted
my_bool opt_reckless_slave = 0;
my_bool opt_enable_named_pipe= 0;
my_bool opt_local_infile, opt_slave_compressed_protocol;
my_bool opt_safe_user_create = 0;
my_bool opt_show_slave_auth_info;
my_bool opt_log_slave_updates= 0;
char *opt_slave_skip_errors;
my_bool opt_slave_allow_batching= 0;

/**
  compatibility option:
    - index usage hints (USE INDEX without a FOR clause) behave as in 5.0
*/
my_bool old_mode;

/*
  Legacy global handlerton. These will be removed (please do not add more).
*/
handlerton *heap_hton;
handlerton *myisam_hton;
handlerton *partition_hton;

uint opt_server_id_bits= 0;
ulong opt_server_id_mask= 0;
my_bool read_only= 0, opt_readonly= 0;
my_bool use_temp_pool, relay_log_purge;
my_bool relay_log_recovery;
my_bool opt_sync_frm, opt_allow_suspicious_udfs;
my_bool opt_secure_auth= 0;
char* opt_secure_file_priv;
my_bool opt_log_slow_admin_statements= 0;
my_bool opt_log_slow_slave_statements= 0;
my_bool lower_case_file_system= 0;
my_bool opt_large_pages= 0;
my_bool opt_super_large_pages= 0;
my_bool opt_myisam_use_mmap= 0;
uint   opt_large_page_size= 0;
volatile uint default_password_lifetime= 0;
#if defined(ENABLED_DEBUG_SYNC)
MYSQL_PLUGIN_IMPORT uint    opt_debug_sync_timeout= 0;
#endif /* defined(ENABLED_DEBUG_SYNC) */
my_bool opt_old_style_user_limits= 0, trust_function_creators= 0;
/*
  True if there is at least one per-hour limit for some user, so we should
  check them before each query (and possibly reset counters when hour is
  changed). False otherwise.
*/
volatile bool mqh_used = 0;
my_bool opt_noacl= 0;
my_bool sp_automatic_privileges= 1;

ulong opt_binlog_rows_event_max_size;
const char *binlog_checksum_default= "NONE";
ulong binlog_checksum_options;
my_bool opt_master_verify_checksum= 0;
my_bool opt_slave_sql_verify_checksum= 1;
const char *binlog_format_names[]= {"MIXED", "STATEMENT", "ROW", NullS};
my_bool enforce_gtid_consistency;
ulong gtid_mode;
const char *gtid_mode_names[]=
{"OFF", "UPGRADE_STEP_1", "UPGRADE_STEP_2", "ON", NullS};
TYPELIB gtid_mode_typelib=
{ array_elements(gtid_mode_names) - 1, "", gtid_mode_names, NULL };

#ifdef HAVE_INITGROUPS
volatile sig_atomic_t calling_initgroups= 0; /**< Used in SIGSEGV handler. */
#endif
const char *timestamp_type_names[]= {"UTC", "SYSTEM", NullS};
ulong opt_log_timestamps;
uint mysqld_port, test_flags, select_errors, dropping_tables, ha_open_options;
uint mysqld_port_timeout;
ulong delay_key_write_options;
uint protocol_version;
uint lower_case_table_names;
ulong tc_heuristic_recover= 0;
ulong back_log, connect_timeout, server_id;
ulong table_cache_size, table_def_size;
ulong table_cache_instances;
ulong table_cache_size_per_instance;
ulong what_to_log;
ulong slow_launch_time;
int32 slave_open_temp_tables;
ulong open_files_limit, max_binlog_size, max_relay_log_size;
ulong slave_trans_retries;
uint  slave_net_timeout;
ulong slave_exec_mode_options;
ulonglong slave_type_conversions_options;
ulong opt_mts_slave_parallel_workers;
ulonglong opt_mts_pending_jobs_size_max;
ulonglong slave_rows_search_algorithms_options;
#ifndef DBUG_OFF
uint slave_rows_last_search_algorithm_used;
#endif
ulong mts_parallel_option;
ulong binlog_cache_size=0;
ulonglong  max_binlog_cache_size=0;
ulong slave_max_allowed_packet= 0;
ulong binlog_stmt_cache_size=0;
my_atomic_rwlock_t opt_binlog_max_flush_queue_time_lock;
int32 opt_binlog_max_flush_queue_time= 0;
ulonglong  max_binlog_stmt_cache_size=0;
ulong query_cache_size=0;
ulong refresh_version;  /* Increments on each reload */
query_id_t global_query_id;
my_atomic_rwlock_t global_query_id_lock;
my_atomic_rwlock_t slave_open_temp_tables_lock;
ulong aborted_threads;
ulong delayed_insert_timeout, delayed_insert_limit, delayed_queue_size;
ulong delayed_insert_threads, delayed_insert_writes, delayed_rows_in_use;
ulong delayed_insert_errors,flush_time;
ulong specialflag=0;
ulong binlog_cache_use= 0, binlog_cache_disk_use= 0;
ulong binlog_stmt_cache_use= 0, binlog_stmt_cache_disk_use= 0;
ulong max_connections, max_connect_errors;
ulong rpl_stop_slave_timeout= LONG_TIMEOUT;
my_bool log_bin_use_v1_row_events= 0;
bool thread_cache_size_specified= false;
bool host_cache_size_specified= false;
bool table_definition_cache_specified= false;

Error_log_throttle err_log_throttle(Log_throttle::LOG_THROTTLE_WINDOW_SIZE,
                                    sql_print_error,
                                    "Error log throttle: %10lu 'Can't create"
                                    " thread to handle new connection'"
                                    " error(s) suppressed");

/**
  Limit of the total number of prepared statements in the server.
  Is necessary to protect the server against out-of-memory attacks.
*/
ulong max_prepared_stmt_count;
/**
  Current total number of prepared statements in the server. This number
  is exact, and therefore may not be equal to the difference between
  `com_stmt_prepare' and `com_stmt_close' (global status variables), as
  the latter ones account for all registered attempts to prepare
  a statement (including unsuccessful ones).  Prepared statements are
  currently connection-local: if the same SQL query text is prepared in
  two different connections, this counts as two distinct prepared
  statements.
*/
ulong prepared_stmt_count=0;
ulong current_pid;
uint sync_binlog_period= 0, sync_relaylog_period= 0,
     sync_relayloginfo_period= 0, sync_masterinfo_period= 0,
     opt_mts_checkpoint_period, opt_mts_checkpoint_group;
ulong expire_logs_days = 0;
/**
  Soft upper limit for number of sp_head objects that can be stored
  in the sp_cache for one connection.
*/
ulong stored_program_cache_size= 0;

const double log_10[] = {
  1e000, 1e001, 1e002, 1e003, 1e004, 1e005, 1e006, 1e007, 1e008, 1e009,
  1e010, 1e011, 1e012, 1e013, 1e014, 1e015, 1e016, 1e017, 1e018, 1e019,
  1e020, 1e021, 1e022, 1e023, 1e024, 1e025, 1e026, 1e027, 1e028, 1e029,
  1e030, 1e031, 1e032, 1e033, 1e034, 1e035, 1e036, 1e037, 1e038, 1e039,
  1e040, 1e041, 1e042, 1e043, 1e044, 1e045, 1e046, 1e047, 1e048, 1e049,
  1e050, 1e051, 1e052, 1e053, 1e054, 1e055, 1e056, 1e057, 1e058, 1e059,
  1e060, 1e061, 1e062, 1e063, 1e064, 1e065, 1e066, 1e067, 1e068, 1e069,
  1e070, 1e071, 1e072, 1e073, 1e074, 1e075, 1e076, 1e077, 1e078, 1e079,
  1e080, 1e081, 1e082, 1e083, 1e084, 1e085, 1e086, 1e087, 1e088, 1e089,
  1e090, 1e091, 1e092, 1e093, 1e094, 1e095, 1e096, 1e097, 1e098, 1e099,
  1e100, 1e101, 1e102, 1e103, 1e104, 1e105, 1e106, 1e107, 1e108, 1e109,
  1e110, 1e111, 1e112, 1e113, 1e114, 1e115, 1e116, 1e117, 1e118, 1e119,
  1e120, 1e121, 1e122, 1e123, 1e124, 1e125, 1e126, 1e127, 1e128, 1e129,
  1e130, 1e131, 1e132, 1e133, 1e134, 1e135, 1e136, 1e137, 1e138, 1e139,
  1e140, 1e141, 1e142, 1e143, 1e144, 1e145, 1e146, 1e147, 1e148, 1e149,
  1e150, 1e151, 1e152, 1e153, 1e154, 1e155, 1e156, 1e157, 1e158, 1e159,
  1e160, 1e161, 1e162, 1e163, 1e164, 1e165, 1e166, 1e167, 1e168, 1e169,
  1e170, 1e171, 1e172, 1e173, 1e174, 1e175, 1e176, 1e177, 1e178, 1e179,
  1e180, 1e181, 1e182, 1e183, 1e184, 1e185, 1e186, 1e187, 1e188, 1e189,
  1e190, 1e191, 1e192, 1e193, 1e194, 1e195, 1e196, 1e197, 1e198, 1e199,
  1e200, 1e201, 1e202, 1e203, 1e204, 1e205, 1e206, 1e207, 1e208, 1e209,
  1e210, 1e211, 1e212, 1e213, 1e214, 1e215, 1e216, 1e217, 1e218, 1e219,
  1e220, 1e221, 1e222, 1e223, 1e224, 1e225, 1e226, 1e227, 1e228, 1e229,
  1e230, 1e231, 1e232, 1e233, 1e234, 1e235, 1e236, 1e237, 1e238, 1e239,
  1e240, 1e241, 1e242, 1e243, 1e244, 1e245, 1e246, 1e247, 1e248, 1e249,
  1e250, 1e251, 1e252, 1e253, 1e254, 1e255, 1e256, 1e257, 1e258, 1e259,
  1e260, 1e261, 1e262, 1e263, 1e264, 1e265, 1e266, 1e267, 1e268, 1e269,
  1e270, 1e271, 1e272, 1e273, 1e274, 1e275, 1e276, 1e277, 1e278, 1e279,
  1e280, 1e281, 1e282, 1e283, 1e284, 1e285, 1e286, 1e287, 1e288, 1e289,
  1e290, 1e291, 1e292, 1e293, 1e294, 1e295, 1e296, 1e297, 1e298, 1e299,
  1e300, 1e301, 1e302, 1e303, 1e304, 1e305, 1e306, 1e307, 1e308
};

time_t server_start_time, flush_status_time;

char server_uuid[UUID_LENGTH+1];
const char *server_uuid_ptr;
char mysql_home[FN_REFLEN], pidfile_name[FN_REFLEN], system_time_zone[30];
char default_logfile_name[FN_REFLEN];
char *default_tz_name;
char log_error_file[FN_REFLEN], glob_hostname[FN_REFLEN];
char mysql_real_data_home[FN_REFLEN],
     lc_messages_dir[FN_REFLEN], reg_ext[FN_EXTLEN],
     mysql_charsets_dir[FN_REFLEN],
     *opt_init_file, *opt_tc_log_file;
char *lc_messages_dir_ptr, *log_error_file_ptr;
char mysql_unpacked_real_data_home[FN_REFLEN];
size_t mysql_unpacked_real_data_home_len;
uint mysql_real_data_home_len, mysql_data_home_len= 1;
uint reg_ext_length;
const key_map key_map_empty(0);
key_map key_map_full(0);                        // Will be initialized later
char logname_path[FN_REFLEN];
char slow_logname_path[FN_REFLEN];
char secure_file_real_path[FN_REFLEN];

DATE_TIME_FORMAT global_date_format, global_datetime_format, global_time_format;
Time_zone *default_tz;

char *mysql_data_home= const_cast<char*>(".");
const char *mysql_real_data_home_ptr= mysql_real_data_home;
char server_version[SERVER_VERSION_LENGTH];
char *mysqld_unix_port, *opt_mysql_tmpdir;

/** name of reference on left expression in rewritten IN subquery */
const char *in_left_expr_name= "<left expr>";
/** name of additional condition */
const char *in_additional_cond= "<IN COND>";
const char *in_having_cond= "<IN HAVING>";

my_decimal decimal_zero;
#ifndef EMBEDDED_LIBRARY
/** Number of connection errors from internal server errors. */
ulong connection_errors_internal= 0;
/** Number of errors when reading the peer address. */
ulong connection_errors_peer_addr= 0;
#endif

/* classes for comparation parsing/processing */
Eq_creator eq_creator;
Ne_creator ne_creator;
Gt_creator gt_creator;
Lt_creator lt_creator;
Ge_creator ge_creator;
Le_creator le_creator;

Rpl_filter* rpl_filter;
Rpl_filter* binlog_filter;

struct system_variables global_system_variables;
struct system_variables max_system_variables;
struct system_status_var global_status_var;

MY_TMPDIR mysql_tmpdir_list;
MY_BITMAP temp_pool;

CHARSET_INFO *system_charset_info, *files_charset_info ;
CHARSET_INFO *national_charset_info, *table_alias_charset;
CHARSET_INFO *character_set_filesystem;
CHARSET_INFO *error_message_charset_info;

MY_LOCALE *my_default_lc_messages;
MY_LOCALE *my_default_lc_time_names;

SHOW_COMP_OPTION have_ssl, have_symlink, have_dlopen, have_query_cache;
SHOW_COMP_OPTION have_geometry, have_rtree_keys;
SHOW_COMP_OPTION have_crypt, have_compress;
SHOW_COMP_OPTION have_profiling;
SHOW_COMP_OPTION have_statement_timeout= SHOW_OPTION_DISABLED;

/* Thread specific variables */

pthread_key(MEM_ROOT**,THR_MALLOC);
bool THR_MALLOC_initialized= false;
pthread_key(THD*, THR_THD);
bool THR_THD_initialized= false;
mysql_mutex_t
  LOCK_status, LOCK_error_log, LOCK_uuid_generator,
  LOCK_crypt,
  LOCK_global_system_variables,
  LOCK_user_conn, LOCK_slave_list, LOCK_active_mi,
  LOCK_error_messages;
mysql_mutex_t LOCK_sql_rand;

/**
  The below lock protects access to two global server variables:
  max_prepared_stmt_count and prepared_stmt_count. These variables
  set the limit and hold the current total number of prepared statements
  in the server, respectively. As PREPARE/DEALLOCATE rate in a loaded
  server may be fairly high, we need a dedicated lock.
*/
mysql_mutex_t LOCK_prepared_stmt_count;

/*
 The below two locks are introudced as guards (second mutex) for
  the global variables sql_slave_skip_counter and slave_net_timeout
  respectively. See fix_slave_skip_counter/fix_slave_net_timeout
  for more details
*/
mysql_mutex_t LOCK_sql_slave_skip_counter;
mysql_mutex_t LOCK_slave_net_timeout;
mysql_mutex_t LOCK_log_throttle_qni;
#ifdef HAVE_OPENSSL
mysql_mutex_t LOCK_des_key_file;
#endif
mysql_rwlock_t LOCK_grant, LOCK_sys_init_connect, LOCK_sys_init_slave;
mysql_rwlock_t LOCK_system_variables_hash;
pthread_t signal_thread_id= 0;
pthread_attr_t connection_attrib;
mysql_mutex_t LOCK_server_started;
mysql_cond_t COND_server_started;
#if !defined (EMBEDDED_LIBRARY) && !defined(_WIN32)
mysql_mutex_t LOCK_socket_listener_active;
mysql_cond_t COND_socket_listener_active;
mysql_mutex_t LOCK_start_signal_handler;
mysql_cond_t COND_start_signal_handler;
#endif

bool mysqld_server_started= false;

File_parser_dummy_hook file_parser_dummy_hook;

/* replication parameters, if master_host is not NULL, we are a slave */
uint report_port= 0;
ulong master_retry_count=0;
char *master_info_file;
char *relay_log_info_file, *report_user, *report_password, *report_host;
char *opt_relay_logname = 0, *opt_relaylog_index_name=0;
char *opt_general_logname, *opt_slow_logname, *opt_bin_logname;

/* Static variables */

static volatile sig_atomic_t kill_in_progress;


static my_bool opt_myisam_log;
static int cleanup_done;
static ulong opt_specialflag;
static char *opt_update_logname;
char *opt_binlog_index_name;
char *mysql_home_ptr, *pidfile_name_ptr;
char *default_auth_plugin;
/** Initial command line arguments (count), after load_defaults().*/
static int defaults_argc;
/**
  Initial command line arguments (arguments), after load_defaults().
  This memory is allocated by @c load_defaults() and should be freed
  using @c free_defaults().
  Do not modify defaults_argc / defaults_argv,
  use remaining_argc / remaining_argv instead to parse the command
  line arguments in multiple steps.
*/
static char **defaults_argv;
/** Remaining command line arguments (count), filtered by handle_options().*/
static int remaining_argc;
/** Remaining command line arguments (arguments), filtered by handle_options().*/
static char **remaining_argv;

bool load_perfschema_engine= false;

int orig_argc;
char **orig_argv;

#if defined(HAVE_OPENSSL) && !defined(HAVE_YASSL)
bool init_rsa_keys(void);
void deinit_rsa_keys(void);
int show_rsa_public_key(THD *thd, SHOW_VAR *var, char *buff);
#endif

Connection_acceptor<Mysqld_socket_listener> *mysqld_socket_acceptor= NULL;
#ifdef _WIN32
Connection_acceptor<Named_pipe_listener> *named_pipe_acceptor= NULL;
Connection_acceptor<Shared_mem_listener> *shared_mem_acceptor= NULL;
#endif

Checkable_rwlock *global_sid_lock= NULL;
Sid_map *global_sid_map= NULL;
Gtid_state *gtid_state= NULL;


void set_remaining_args(int argc, char **argv)
{
  remaining_argc= argc;
  remaining_argv= argv;
}
/* 
  Multiple threads of execution use the random state maintained in global
  sql_rand to generate random numbers. sql_rnd_with_mutex use mutex
  LOCK_sql_rand to protect sql_rand across multiple instantiations that use
  sql_rand to generate random numbers.
 */
ulong sql_rnd_with_mutex()
{
  mysql_mutex_lock(&LOCK_sql_rand);
  ulong tmp=(ulong) (my_rnd(&sql_rand) * 0xffffffff); /* make all bits random */
  mysql_mutex_unlock(&LOCK_sql_rand);
  return tmp;
}


/**
  A log message for the error log, buffered in memory.
  Log messages are temporarily buffered when generated before the error log
  is initialized, and then printed once the error log is ready.
*/
class Buffered_log : public Sql_alloc
{
public:
  Buffered_log(enum loglevel level, const char *message);

  ~Buffered_log()
  {}

  void print(void);

private:
  /** Log message level. */
  enum loglevel m_level;
  /** Log message text. */
  String m_message;
};

/**
  Constructor.
  @param level          the message log level
  @param message        the message text
*/
Buffered_log::Buffered_log(enum loglevel level, const char *message)
  : m_level(level), m_message()
{
  m_message.copy(message, strlen(message), &my_charset_latin1);
}

/**
  Print a buffered log to the real log file.
*/
void Buffered_log::print()
{
  if (!(static_cast<ulong>(m_level) < log_error_verbosity))
    return;

  /*
    Since messages are buffered, they can be printed out
    of order with other entries in the log.
    Add "Buffered xxx" to the message text to prevent confusion.
  */
  switch(m_level)
  {
  case ERROR_LEVEL:
    sql_print_error("Buffered error: %s", m_message.c_ptr_safe());
    break;
  case WARNING_LEVEL:
    sql_print_warning("Buffered warning: %s", m_message.c_ptr_safe());
    break;
  case INFORMATION_LEVEL:
    /*
      Messages printed as "information" still end up in the mysqld *error* log,
      but with a [Note] tag instead of an [ERROR] tag.
    */
    sql_print_information("Buffered note: %s", m_message.c_ptr_safe());
    break;
  }
}

/**
  Collection of all the buffered log messages.
*/
class Buffered_logs
{
public:
  Buffered_logs()
  {}

  ~Buffered_logs()
  {}

  void init();
  void cleanup();

  void buffer(enum loglevel m_level, const char *msg);
  void print();
private:
  /**
    Memory root to use to store buffered logs.
    This memory root lifespan is between init and cleanup.
    Once the buffered logs are printed, they are not needed anymore,
    and all the memory used is reclaimed.
  */
  MEM_ROOT m_root;
  /** List of buffered log messages. */
  List<Buffered_log> m_list;
};

void Buffered_logs::init()
{
  init_alloc_root(key_memory_buffered_logs, &m_root, 1024, 0);
}

void Buffered_logs::cleanup()
{
  m_list.delete_elements();
  free_root(&m_root, MYF(0));
}

/**
  Add a log message to the buffer.
*/
void Buffered_logs::buffer(enum loglevel level, const char *msg)
{
  /*
    Do not let Sql_alloc::operator new(size_t) allocate memory,
    there is no memory root associated with the main() thread.
    Give explicitly the proper memory root to use to
    Sql_alloc::operator new(size_t, MEM_ROOT *) instead.
  */
  Buffered_log *log= new (&m_root) Buffered_log(level, msg);
  if (log)
    m_list.push_back(log, &m_root);
}

/**
  Print buffered log messages.
*/
void Buffered_logs::print()
{
  Buffered_log *log;
  List_iterator_fast<Buffered_log> it(m_list);
  while ((log= it++))
    log->print();
}

/** Logs reported before a logger is available. */
static Buffered_logs buffered_logs;

/**
  Error reporter that buffer log messages.
  @param level          log message level
  @param format         log message format string
*/
C_MODE_START
static void buffered_option_error_reporter(enum loglevel level,
                                           const char *format, ...)
{
  va_list args;
  char buffer[1024];

  va_start(args, format);
  my_vsnprintf(buffer, sizeof(buffer), format, args);
  va_end(args);
  buffered_logs.buffer(level, buffer);
}


/**
  Character set and collation error reporter that prints to sql error log.
  @param level          log message level
  @param format         log message format string

  This routine is used to print character set and collation
  warnings and errors inside an already running mysqld server,
  e.g. when a character set or collation is requested for the very first time
  and its initialization does not go well for some reasons.

  Note: At early mysqld initialization stage,
  when error log is not yet available,
  we use buffered_option_error_reporter() instead,
  to print general character set subsystem initialization errors,
  such as Index.xml syntax problems, bad XML tag hierarchy, etc.
*/
static void charset_error_reporter(enum loglevel level,
                                   const char *format, ...)
{
  va_list args;
  va_start(args, format);
  error_log_print(level, format, args);
  va_end(args);
}
C_MODE_END

struct rand_struct sql_rand; ///< used by sql_class.cc:THD::THD()

#ifndef EMBEDDED_LIBRARY
struct passwd *user_info= NULL;
#ifndef _WIN32
static pthread_t main_thread_id;
#endif // !_WIN32
#endif // !EMBEDDED_LIBRARY

/* OS specific variables */

#ifdef _WIN32
#include <process.h>

static bool start_mode=0, use_opt_args;
static int opt_argc;
static char **opt_argv;

#if !defined(EMBEDDED_LIBRARY)
static mysql_mutex_t LOCK_handler_count;
static mysql_cond_t COND_handler_count;
static HANDLE hEventShutdown;
char *shared_memory_base_name= default_shared_memory_base_name;
my_bool opt_enable_shared_memory;
static char shutdown_event_name[40];
#include "nt_servc.h"
static   NTService  Service;        ///< Service object for WinNT
#endif /* EMBEDDED_LIBRARY */
#endif /* _WIN32 */

#ifndef EMBEDDED_LIBRARY
bool mysqld_embedded=0;
#else
bool mysqld_embedded=1;
#endif

static my_bool plugins_are_initialized= FALSE;

#ifndef DBUG_OFF
static const char* default_dbug_option;
#endif
ulong query_cache_min_res_unit= QUERY_CACHE_MIN_RESULT_DATA_SIZE;
Query_cache query_cache;

my_bool opt_use_ssl  = 0;
char *opt_ssl_ca= NULL, *opt_ssl_capath= NULL, *opt_ssl_cert= NULL,
     *opt_ssl_cipher= NULL, *opt_ssl_key= NULL, *opt_ssl_crl= NULL,
     *opt_ssl_crlpath= NULL;

#ifdef HAVE_OPENSSL
#include <openssl/crypto.h>
#ifndef HAVE_YASSL
typedef struct CRYPTO_dynlock_value
{
  mysql_rwlock_t lock;
} openssl_lock_t;

static openssl_lock_t *openssl_stdlocks;
static openssl_lock_t *openssl_dynlock_create(const char *, int);
static void openssl_dynlock_destroy(openssl_lock_t *, const char *, int);
static void openssl_lock_function(int, int, const char *, int);
static void openssl_lock(int, openssl_lock_t *, const char *, int);
static unsigned long openssl_id_function();
#endif
char *des_key_file;
#ifndef EMBEDDED_LIBRARY
struct st_VioSSLFd *ssl_acceptor_fd;
#endif
#endif /* HAVE_OPENSSL */

/* Function declarations */

pthread_handler_t signal_hand(void *arg);
static int mysql_init_variables(void);
static int get_options(int *argc_ptr, char ***argv_ptr);
static void add_terminator(vector<my_option> *options);
extern "C" my_bool mysqld_get_one_option(int, const struct my_option *, char *);
static void set_server_version(void);
static int init_thread_environment();
static char *get_relative_path(const char *path);
static int fix_paths(void);
static bool read_init_file(char *file_name);
static void clean_up(bool print_message);
static int test_if_case_insensitive(const char *dir_name);
static void end_ssl();

#ifndef EMBEDDED_LIBRARY
static bool pid_file_created= false;
static void usage(void);
static void clean_up_mutexes(void);
static void create_pid_file();
static void mysqld_exit(int exit_code) __attribute__((noreturn));
static void delete_pid_file(myf flags);
#endif


#ifndef EMBEDDED_LIBRARY
/****************************************************************************
** Code to end mysqld
****************************************************************************/

/**
  This class implements callback function used by close_connections()
  to set KILL_CONNECTION flag on all thds in thd list.
  If m_kill_dump_thread_flag is not set it kills all other threads
  except dump threads. If this flag is set, it kills dump threads.
*/
class Set_kill_conn : public Do_THD_Impl
{
private:
  int m_dump_thread_count;
  bool m_kill_dump_threads_flag;
public:
  Set_kill_conn()
    : m_dump_thread_count(0),
      m_kill_dump_threads_flag(false)
  {}

  void set_dump_thread_flag()
  {
    m_kill_dump_threads_flag= true;
  }

  int get_dump_thread_count() const
  {
    return m_dump_thread_count;
  }

  virtual void operator()(THD *killing_thd)
  {
    DBUG_PRINT("quit",("Informing thread %ld that it's time to die",
                       killing_thd->thread_id));
    if (!m_kill_dump_threads_flag)
    {
      // We skip slave threads & scheduler on this first loop through.
      if (killing_thd->slave_thread)
        return;

      if (killing_thd->get_command() == COM_BINLOG_DUMP ||
          killing_thd->get_command() == COM_BINLOG_DUMP_GTID)
      {
        ++m_dump_thread_count;
        return;
      }
      DBUG_EXECUTE_IF("Check_dump_thread_is_alive",
                      {
                        DBUG_ASSERT(killing_thd->get_command() != COM_BINLOG_DUMP &&
                                    killing_thd->get_command() != COM_BINLOG_DUMP_GTID);
                      };);
    }
    mysql_mutex_lock(&killing_thd->LOCK_thd_data);
    killing_thd->killed= THD::KILL_CONNECTION;
    MYSQL_CALLBACK(Connection_handler_manager::event_functions,
                   post_kill_notification, (killing_thd));
    if (killing_thd->mysys_var)
    {
      mysql_mutex_lock(&killing_thd->mysys_var->mutex);
      killing_thd->mysys_var->abort= 1;
      if (killing_thd->mysys_var->current_cond)
      {
        mysql_mutex_lock(killing_thd->mysys_var->current_mutex);
        mysql_cond_broadcast(killing_thd->mysys_var->current_cond);
        mysql_mutex_unlock(killing_thd->mysys_var->current_mutex);
      }
      mysql_mutex_unlock(&killing_thd->mysys_var->mutex);
    }
    mysql_mutex_unlock(&killing_thd->LOCK_thd_data);
  }
};

/**
  This class implements callback function used by close_connections()
  to close vio connection for all thds in thd list
*/
class Call_close_conn : public Do_THD_Impl
{
public:
  Call_close_conn()
  {}

  virtual void operator()(THD *closing_thd)
  {
    if (closing_thd->vio_ok())
    {
      sql_print_warning(ER_DEFAULT(ER_FORCING_CLOSE),my_progname,
                        closing_thd->thread_id,
                        (closing_thd->main_security_ctx.user ?
                         closing_thd->main_security_ctx.user : ""));
      close_connection(closing_thd);
    }
  }
};

static void close_connections(void)
{
  DBUG_ENTER("close_connections");

  Per_thread_connection_handler::kill_blocked_pthreads();

  uint dump_thread_count= 0;
  uint dump_thread_kill_retries= 8;

#if !defined(_WIN32)
  /*
    Kill the socket listener.
    The main thread will then set socket_listener_active= false,
    and wait for us to finish all the cleanup below.
   */
  mysql_mutex_lock(&LOCK_socket_listener_active);
  while (socket_listener_active)
  {
    DBUG_PRINT("info",("Killing socket listener"));
    if (pthread_kill(main_thread_id, thr_client_alarm))
    {
      DBUG_ASSERT(false);
      break;
    }
    mysql_cond_wait(&COND_socket_listener_active,
                    &LOCK_socket_listener_active);
  }
  mysql_mutex_unlock(&LOCK_socket_listener_active);
#endif /* _WIN32 */

  // Clean up connection acceptors
  if (mysqld_socket_acceptor != NULL)
  {
    delete mysqld_socket_acceptor;
    mysqld_socket_acceptor= NULL;
  }
#ifdef _WIN32
  if (named_pipe_acceptor != NULL)
  {
    delete named_pipe_acceptor;
    named_pipe_acceptor= NULL;
  }
  if (shared_mem_acceptor != NULL)
  {
    delete shared_mem_acceptor;
    shared_mem_acceptor= NULL;
  }
#endif
  end_thr_alarm(0);      // Abort old alarms.

  /*
    First signal all threads that it's time to die
    This will give the threads some time to gracefully abort their
    statements and inform their clients that the server is about to die.
  */

  Global_THD_manager *thd_manager= Global_THD_manager::get_instance();
  sql_print_information("Giving %d client threads a chance to die gracefully",
                        static_cast<int>(thd_manager->get_thd_count()));

  Set_kill_conn set_kill_conn;
  thd_manager->do_for_all_thd(&set_kill_conn);
  sql_print_information("Shutting down slave threads");
  end_slave();

  if (set_kill_conn.get_dump_thread_count())
  {
    /*
      Replication dump thread should be terminated after the clients are
      terminated. Wait for few more seconds for other sessions to end.
     */
    while (thd_manager->get_thd_count() > dump_thread_count &&
           dump_thread_kill_retries)
    {
      sleep(1);
      dump_thread_kill_retries--;
    }
    set_kill_conn.set_dump_thread_flag();
    thd_manager->do_for_all_thd(&set_kill_conn);
  }
  if (thd_manager->get_thd_count() > 0)
    sleep(2);         // Give threads time to die

  /*
    Force remaining threads to die by closing the connection to the client
    This will ensure that threads that are waiting for a command from the
    client on a blocking read call are aborted.
  */

  sql_print_information("Forcefully disconnecting %d remaining clients",
                        static_cast<int>(thd_manager->get_thd_count()));

  Call_close_conn call_close_conn;
  thd_manager->do_for_all_thd(&call_close_conn);

  /*
    All threads have now been aborted. Stop event scheduler thread
    after aborting all client connections, otherwise user may
    start/stop event scheduler after Events::deinit() deallocates
    scheduler object(static member in Events class)
  */
  Events::deinit();
  DBUG_PRINT("quit",("Waiting for threads to die (count=%u)",
                     thd_manager->get_thd_count()));
  thd_manager->wait_till_no_thd();

  close_active_mi();
  DBUG_PRINT("quit",("close_connections thread"));
  DBUG_VOID_RETURN;
}


void kill_mysql(void)
{
  DBUG_ENTER("kill_mysql");

#if defined(_WIN32)
  {
    if (!SetEvent(hEventShutdown))
    {
      DBUG_PRINT("error",("Got error: %ld from SetEvent",GetLastError()));
    }
    /*
      or:
      HANDLE hEvent=OpenEvent(0, FALSE, "MySqlShutdown");
      SetEvent(hEventShutdown);
      CloseHandle(hEvent);
    */
  }
#else
  if (pthread_kill(signal_thread_id, MYSQL_KILL_SIGNAL))
  {
    DBUG_PRINT("error",("Got error %d from pthread_kill",errno)); /* purecov: inspected */
  }
#endif
  DBUG_PRINT("quit",("After pthread_kill"));
  DBUG_VOID_RETURN;
}

extern "C" void print_signal_warning(int sig)
{
  sql_print_warning("Got signal %d from thread %ld", sig,my_thread_id());
#ifdef SIGNAL_HANDLER_RESET_ON_DELIVERY
  my_sigset(sig,print_signal_warning);    /* int. thread system calls */
#endif
#if !defined(_WIN32)
  if (sig == SIGALRM)
    alarm(2);         /* reschedule alarm */
#endif
}

static void init_error_log_mutex()
{
  mysql_mutex_init(key_LOCK_error_log, &LOCK_error_log, MY_MUTEX_INIT_FAST);
}


static void clean_up_error_log_mutex()
{
  mysql_mutex_destroy(&LOCK_error_log);
}

extern "C" void unireg_abort(int exit_code)
{
  DBUG_ENTER("unireg_abort");

  if (opt_help)
    usage();
  if (exit_code)
    sql_print_error("Aborting\n");

#ifndef _WIN32
  if (signal_thread_id != 0)
  {
    pthread_kill(signal_thread_id, MYSQL_KILL_SIGNAL);
    pthread_join(signal_thread_id, NULL);
  }
  signal_thread_id= 0;
#endif

  clean_up(!opt_help && (exit_code || !opt_bootstrap)); /* purecov: inspected */
  DBUG_PRINT("quit",("done with cleanup in unireg_abort"));
  mysqld_exit(exit_code);
}

static void mysqld_exit(int exit_code)
{
  mysql_audit_finalize();
  clean_up_mutexes();
  my_end(opt_endinfo ? MY_CHECK_ERROR | MY_GIVE_INFO : 0);
  local_message_hook= my_message_local_stderr;
  clean_up_error_log_mutex();
#ifdef WITH_PERFSCHEMA_STORAGE_ENGINE
  shutdown_performance_schema();
#endif
#if defined(_WIN32)
  if (Service.IsNT() && start_mode)
  {
    Service.Stop();
  }
  else
  {
    Service.SetShutdownEvent(0);
    if (hEventShutdown)
      CloseHandle(hEventShutdown);
  }
#endif
  exit(exit_code); /* purecov: inspected */
}

#endif /* !EMBEDDED_LIBRARY */

/**
   GTID cleanup destroys objects and reset their pointer.
   Function is reentrant.
*/
void gtid_server_cleanup()
{
  delete gtid_state;
  delete global_sid_map;
  delete global_sid_lock;
  global_sid_lock= NULL;
  global_sid_map= NULL;
  gtid_state= NULL;
}

/**
   GTID initialization.

   @return true if allocation does not succeed
           false if OK
*/
bool gtid_server_init()
{
  bool res=
    (!(global_sid_lock= new Checkable_rwlock) ||
     !(global_sid_map= new Sid_map(global_sid_lock)) ||
     !(gtid_state= new Gtid_state(global_sid_lock, global_sid_map)));
  if (res)
  {
    gtid_server_cleanup();
  }
  return res;
}


void clean_up(bool print_message)
{
  DBUG_PRINT("exit",("clean_up"));
  if (cleanup_done++)
    return; /* purecov: inspected */

  stop_handle_manager();
  release_ddl_log();

  memcached_shutdown();

  /*
    make sure that handlers finish up
    what they have that is dependent on the binlog
  */
  if ((opt_help == 0) || (opt_verbose > 0))
    sql_print_information("Binlog end");
  ha_binlog_end(current_thd);

  injector::free_instance();
  mysql_bin_log.cleanup();
  gtid_server_cleanup();

#ifdef HAVE_REPLICATION
  if (use_slave_mask)
    bitmap_free(&slave_error_mask);
#endif
  my_tz_free();
  my_dboptions_cache_free();
  ignore_db_dirs_free();
#ifndef NO_EMBEDDED_ACCESS_CHECKS
  servers_free(1);
  acl_free(1);
  grant_free();
#endif
  query_cache.destroy();
  hostname_cache_free();
  item_user_lock_free();
  lex_free();       /* Free some memory */
  item_create_cleanup();
  if (!opt_noacl)
  {
#ifdef HAVE_DLOPEN
    udf_free();
#endif
  }
  table_def_start_shutdown();
  plugin_shutdown();
  ha_end();
  if (tc_log)
    tc_log->close();
  delegates_destroy();
  transaction_cache_free();
  table_def_free();
  mdl_destroy();
  key_caches.delete_elements((void (*)(const char*, uchar*)) free_key_cache);
  multi_keycache_free();
  free_status_vars();
  end_thr_alarm(1);     /* Free allocated memory */
  query_logger.cleanup();
  my_free_open_file_info();
  if (defaults_argv)
    free_defaults(defaults_argv);
  free_tmpdir(&mysql_tmpdir_list);
  my_free(opt_bin_logname);
  bitmap_free(&temp_pool);
  free_max_user_conn();
#ifdef HAVE_REPLICATION
  end_slave_list();
#endif
  delete binlog_filter;
  delete rpl_filter;
  end_ssl();
  vio_end();
  my_regex_end();
#if defined(ENABLED_DEBUG_SYNC)
  /* End the debug sync facility. See debug_sync.cc. */
  debug_sync_end();
#endif /* defined(ENABLED_DEBUG_SYNC) */

#ifndef EMBEDDED_LIBRARY
  delete_pid_file(MYF(0));
#endif

  if (print_message && my_default_lc_messages && server_start_time)
    sql_print_information(ER_DEFAULT(ER_SHUTDOWN_COMPLETE),my_progname);
  cleanup_errmsgs();

#ifndef EMBEDDED_LIBRARY
  Connection_handler_manager::destroy_instance();
#endif

  mysql_client_plugin_deinit();
  finish_client_errs();
  (void) my_error_unregister(ER_ERROR_FIRST, ER_ERROR_LAST); // finish server errs
  DBUG_PRINT("quit", ("Error messages freed"));

  my_atomic_rwlock_destroy(&opt_binlog_max_flush_queue_time_lock);
  my_atomic_rwlock_destroy(&global_query_id_lock);
  free_charsets();
  sys_var_end();
  Global_THD_manager::destroy_instance();

  my_free(const_cast<char*>(log_bin_basename));
  my_free(const_cast<char*>(log_bin_index));
#ifndef EMBEDDED_LIBRARY
  my_free(const_cast<char*>(relay_log_basename));
  my_free(const_cast<char*>(relay_log_index));
#endif
  free_list(opt_plugin_load_list_ptr);

  if (THR_THD_initialized)
  {
    THR_THD_initialized= false;
    (void) pthread_key_delete(THR_THD);
  }

  if (THR_MALLOC_initialized)
  {
    THR_MALLOC_initialized= false;
    (void) pthread_key_delete(THR_MALLOC);
  }

#ifdef HAVE_MY_TIMER
  if (have_statement_timeout == SHOW_OPTION_YES)
    my_timer_deinitialize();

  have_statement_timeout= SHOW_OPTION_DISABLED;
#endif

  /*
    The following lines may never be executed as the main thread may have
    killed us
  */
  DBUG_PRINT("quit", ("done with cleanup"));
} /* clean_up */


#ifndef EMBEDDED_LIBRARY

static void clean_up_mutexes()
{
  mysql_rwlock_destroy(&LOCK_grant);
  mysql_mutex_destroy(&LOCK_log_throttle_qni);
  mysql_mutex_destroy(&LOCK_status);
  mysql_mutex_destroy(&LOCK_manager);
  mysql_mutex_destroy(&LOCK_crypt);
  mysql_mutex_destroy(&LOCK_user_conn);
#ifdef HAVE_OPENSSL
  mysql_mutex_destroy(&LOCK_des_key_file);
#ifndef HAVE_YASSL
  for (int i= 0; i < CRYPTO_num_locks(); ++i)
    mysql_rwlock_destroy(&openssl_stdlocks[i].lock);
  OPENSSL_free(openssl_stdlocks);
#endif
#endif
  mysql_mutex_destroy(&LOCK_active_mi);
  mysql_rwlock_destroy(&LOCK_sys_init_connect);
  mysql_rwlock_destroy(&LOCK_sys_init_slave);
  mysql_mutex_destroy(&LOCK_global_system_variables);
  mysql_rwlock_destroy(&LOCK_system_variables_hash);
  mysql_mutex_destroy(&LOCK_uuid_generator);
  mysql_mutex_destroy(&LOCK_sql_rand);
  mysql_mutex_destroy(&LOCK_prepared_stmt_count);
  mysql_mutex_destroy(&LOCK_sql_slave_skip_counter);
  mysql_mutex_destroy(&LOCK_slave_net_timeout);
  mysql_mutex_destroy(&LOCK_error_messages);
  mysql_cond_destroy(&COND_manager);
#ifdef _WIN32
  mysql_cond_destroy(&COND_handler_count);
  mysql_mutex_destroy(&LOCK_handler_count);
#endif
#ifndef _WIN32
  mysql_cond_destroy(&COND_socket_listener_active);
  mysql_mutex_destroy(&LOCK_socket_listener_active);
  mysql_cond_destroy(&COND_start_signal_handler);
  mysql_mutex_destroy(&LOCK_start_signal_handler);
#endif
}


/****************************************************************************
** Init IP and UNIX socket
****************************************************************************/

static void set_ports()
{
  char  *env;
  if (!mysqld_port && !opt_disable_networking)
  {         // Get port if not from commandline
    mysqld_port= MYSQL_PORT;

    /*
      if builder specifically requested a default port, use that
      (even if it coincides with our factory default).
      only if they didn't do we check /etc/services (and, failing
      on that, fall back to the factory default of 3306).
      either default can be overridden by the environment variable
      MYSQL_TCP_PORT, which in turn can be overridden with command
      line options.
    */

#if MYSQL_PORT_DEFAULT == 0
    struct  servent *serv_ptr;
    if ((serv_ptr= getservbyname("mysql", "tcp")))
      mysqld_port= ntohs((u_short) serv_ptr->s_port); /* purecov: inspected */
#endif
    if ((env = getenv("MYSQL_TCP_PORT")))
      mysqld_port= (uint) atoi(env);    /* purecov: inspected */
  }
  if (!mysqld_unix_port)
  {
#ifdef _WIN32
    mysqld_unix_port= (char*) MYSQL_NAMEDPIPE;
#else
    mysqld_unix_port= (char*) MYSQL_UNIX_ADDR;
#endif
    if ((env = getenv("MYSQL_UNIX_PORT")))
      mysqld_unix_port= env;      /* purecov: inspected */
  }
}


#if !defined(_WIN32)
/* Change to run as another user if started with --user */

static struct passwd *check_user(const char *user)
{
  struct passwd *tmp_user_info;
  uid_t user_id= geteuid();

  // Don't bother if we aren't superuser
  if (user_id)
  {
    if (user)
    {
      /* Don't give a warning, if real user is same as given with --user */
      tmp_user_info= getpwnam(user);
      if ((!tmp_user_info || user_id != tmp_user_info->pw_uid))
        sql_print_warning(
                    "One can only use the --user switch if running as root\n");
    }
    return NULL;
  }
  if (!user)
  {
    if (!opt_bootstrap && !opt_help)
    {
      sql_print_error("Fatal error: Please read \"Security\" section of the manual to find out how to run mysqld as root!\n");
      unireg_abort(1);
    }
    return NULL;
  }
  /* purecov: begin tested */
  if (!strcmp(user,"root"))
    return NULL;                        // Avoid problem with dynamic libraries

  if (!(tmp_user_info= getpwnam(user)))
  {
    // Allow a numeric uid to be used
    const char *pos;
    for (pos= user; my_isdigit(mysqld_charset,*pos); pos++) ;
    if (*pos)                                   // Not numeric id
      goto err;
    if (!(tmp_user_info= getpwuid(atoi(user))))
      goto err;
  }
  return tmp_user_info;
  /* purecov: end */

err:
  sql_print_error("Fatal error: Can't change to run as user '%s' ;  Please check that the user exists!\n",user);
  unireg_abort(1);

#ifdef PR_SET_DUMPABLE
  if (test_flags & TEST_CORE_ON_SIGNAL)
  {
    /* inform kernel that process is dumpable */
    (void) prctl(PR_SET_DUMPABLE, 1);
  }
#endif

  return NULL;
}

static void set_user(const char *user, struct passwd *user_info_arg)
{
  /* purecov: begin tested */
  DBUG_ASSERT(user_info_arg != 0);
#ifdef HAVE_INITGROUPS
  /*
    We can get a SIGSEGV when calling initgroups() on some systems when NSS
    is configured to use LDAP and the server is statically linked.  We set
    calling_initgroups as a flag to the SIGSEGV handler that is then used to
    output a specific message to help the user resolve this problem.
  */
  calling_initgroups= 1;
  initgroups((char*) user, user_info_arg->pw_gid);
  calling_initgroups= 0;
#endif
  if (setgid(user_info_arg->pw_gid) == -1)
  {
    sql_print_error("setgid: %s", strerror(errno));
    unireg_abort(1);
  }
  if (setuid(user_info_arg->pw_uid) == -1)
  {
    sql_print_error("setuid: %s", strerror(errno));
    unireg_abort(1);
  }
  /* purecov: end */
}


static void set_effective_user(struct passwd *user_info_arg)
{
  DBUG_ASSERT(user_info_arg != 0);
  if (setregid((gid_t)-1, user_info_arg->pw_gid) == -1)
  {
    sql_print_error("setregid: %s", strerror(errno));
    unireg_abort(1);
  }
  if (setreuid((uid_t)-1, user_info_arg->pw_uid) == -1)
  {
    sql_print_error("setreuid: %s", strerror(errno));
    unireg_abort(1);
  }
}


/** Change root user if started with @c --chroot . */
static void set_root(const char *path)
{
  if (chroot(path) == -1)
  {
    sql_print_error("chroot: %s", strerror(errno));
    unireg_abort(1);
  }
  my_setwd("/", MYF(0));
}
#endif // !_WIN32


static void network_init(void)
{
  std::string unix_sock_name= "";

  if (opt_bootstrap)
    return;

  set_ports();

#ifdef HAVE_SYS_UN_H
  unix_sock_name= mysqld_unix_port ? mysqld_unix_port : "";
#endif

  if (!opt_disable_networking || unix_sock_name != "")
  {
    std::string bind_addr_str= my_bind_addr_str ? my_bind_addr_str : "";

    Mysqld_socket_listener *mysqld_socket_listener=
      new (std::nothrow) Mysqld_socket_listener(bind_addr_str,
                                                mysqld_port, back_log,
                                                mysqld_port_timeout,
                                                unix_sock_name);
    if (mysqld_socket_listener == NULL)
      unireg_abort(1);

    mysqld_socket_acceptor=
      new (std::nothrow) Connection_acceptor<Mysqld_socket_listener>(mysqld_socket_listener);
    if (mysqld_socket_acceptor == NULL)
    {
      delete mysqld_socket_listener;
      unireg_abort(1);
    }

    if (mysqld_socket_acceptor->init_connection_acceptor())
    {
      delete mysqld_socket_acceptor;
      unireg_abort(1);
    }

    if (report_port == 0)
      report_port= mysqld_port;

    if (!opt_disable_networking)
      DBUG_ASSERT(report_port != 0);
  }
#ifdef _WIN32
  // Create named pipe
  if (opt_enable_named_pipe)
  {
    std::string pipe_name= mysqld_unix_port ? mysqld_unix_port : "";

    Named_pipe_listener *named_pipe_listener=
      new (std::nothrow) Named_pipe_listener(&pipe_name);
    if (named_pipe_listener == NULL)
      unireg_abort(1);

    named_pipe_acceptor=
      new (std::nothrow) Connection_acceptor<Named_pipe_listener>(named_pipe_listener);
    if (named_pipe_acceptor == NULL)
    {
      delete named_pipe_listener;
      unireg_abort(1);
    }

    if (named_pipe_acceptor->init_connection_acceptor())
    {
      delete named_pipe_acceptor;
      unireg_abort(1);
    }
  }

  // Setup shared_memory acceptor
  if (opt_enable_shared_memory)
  {
    std::string shared_mem_base_name= shared_memory_base_name ? shared_memory_base_name : "";

    Shared_mem_listener *shared_mem_listener=
      new (std::nothrow) Shared_mem_listener(&shared_mem_base_name);
    if (shared_mem_listener == NULL)
      unireg_abort(1);

    shared_mem_acceptor=
      new (std::nothrow) Connection_acceptor<Shared_mem_listener>(shared_mem_listener);
    if (shared_mem_acceptor == NULL)
    {
      delete shared_mem_acceptor;
      unireg_abort(1);
    }

    if (shared_mem_acceptor->init_connection_acceptor())
    {
      delete shared_mem_acceptor;
      unireg_abort(1);
    }
  }
#endif // _WIN32
}

#ifdef _WIN32
static uint handler_count= 0;


static inline void decrement_handler_count()
{
  mysql_mutex_lock(&LOCK_handler_count);
  handler_count--;
  mysql_cond_signal(&COND_handler_count);
  mysql_mutex_unlock(&LOCK_handler_count);
}


pthread_handler_t socket_conn_event_handler(void *arg)
{
  my_thread_init();

  Connection_acceptor<Mysqld_socket_listener> *conn_acceptor=
    static_cast<Connection_acceptor<Mysqld_socket_listener>*>(arg);
  conn_acceptor->connection_event_loop();

  decrement_handler_count();
  my_thread_end();
  return 0;
}


pthread_handler_t named_pipe_conn_event_handler(void *arg)
{
  my_thread_init();

  Connection_acceptor<Named_pipe_listener> *conn_acceptor=
    static_cast<Connection_acceptor<Named_pipe_listener>*>(arg);
  conn_acceptor->connection_event_loop();

  decrement_handler_count();
  my_thread_end();
  return 0;
}


pthread_handler_t shared_mem_conn_event_handler(void *arg)
{
  my_thread_init();

  Connection_acceptor<Shared_mem_listener> *conn_acceptor=
    static_cast<Connection_acceptor<Shared_mem_listener>*>(arg);
  conn_acceptor->connection_event_loop();

  decrement_handler_count();
  my_thread_end();
  return 0;
}


void setup_conn_event_handler_threads()
{
  pthread_t hThread;

  DBUG_ENTER("handle_connections_methods");

  if ((!have_tcpip || opt_disable_networking) &&
      !opt_enable_shared_memory && !opt_enable_named_pipe)
  {
    sql_print_error("TCP/IP, --shared-memory, or --named-pipe should be configured on NT OS");
    unireg_abort(1);        // Will not return
  }

  mysql_mutex_lock(&LOCK_handler_count);
  handler_count=0;

  if (opt_enable_named_pipe)
  {
    int error= mysql_thread_create(key_thread_handle_con_namedpipes,
                                   &hThread, &connection_attrib,
                                   named_pipe_conn_event_handler,
                                   named_pipe_acceptor);
    if (!error)
      handler_count++;
    else
      sql_print_warning("Can't create thread to handle named pipes"
                        " (errno= %d)", error);
  }

  if (have_tcpip && !opt_disable_networking)
  {
    int error= mysql_thread_create(key_thread_handle_con_sockets,
                                   &hThread, &connection_attrib,
                                   socket_conn_event_handler,
                                   mysqld_socket_acceptor);
    if (!error)
      handler_count++;
    else
      sql_print_warning("Can't create thread to handle TCP/IP (errno= %d)",
                        error);
  }

  if (opt_enable_shared_memory)
  {
    int error= mysql_thread_create(key_thread_handle_con_sharedmem,
                                   &hThread, &connection_attrib,
                                   shared_mem_conn_event_handler,
                                   shared_mem_acceptor);
    if (!error)
      handler_count++;
    else
      sql_print_warning("Can't create thread to handle shared memory"
                        " (errno= %d)", error);
  }

  // Block until all connection listener threads have exited.
  while (handler_count > 0)
    mysql_cond_wait(&COND_handler_count, &LOCK_handler_count);
  mysql_mutex_unlock(&LOCK_handler_count);
  DBUG_VOID_RETURN;
}


/*
  On Windows, we use native SetConsoleCtrlHandler for handle events like Ctrl-C
  with graceful shutdown.
  Also, we do not use signal(), but SetUnhandledExceptionFilter instead - as it
  provides possibility to pass the exception to just-in-time debugger, collect
  dumps and potentially also the exception and thread context used to output
  callstack.
*/

static BOOL WINAPI console_event_handler( DWORD type )
{
  DBUG_ENTER("console_event_handler");
  if(type == CTRL_C_EVENT)
  {
     /*
       Do not shutdown before startup is finished and shutdown
       thread is initialized. Otherwise there is a race condition
       between main thread doing initialization and CTRL-C thread doing
       cleanup, which can result into crash.
     */
     if(hEventShutdown)
       kill_mysql();
     else
       sql_print_warning("CTRL-C ignored during startup");
     DBUG_RETURN(TRUE);
  }
  DBUG_RETURN(FALSE);
}


#ifdef DEBUG_UNHANDLED_EXCEPTION_FILTER
#define DEBUGGER_ATTACH_TIMEOUT 120
/*
  Wait for debugger to attach and break into debugger. If debugger is not attached,
  resume after timeout.
*/
static void wait_for_debugger(int timeout_sec)
{
   if(!IsDebuggerPresent())
   {
     int i;
     printf("Waiting for debugger to attach, pid=%u\n",GetCurrentProcessId());
     fflush(stdout);
     for(i= 0; i < timeout_sec; i++)
     {
       Sleep(1000);
       if(IsDebuggerPresent())
       {
         /* Break into debugger */
         __debugbreak();
         return;
       }
     }
     printf("pid=%u, debugger not attached after %d seconds, resuming\n",GetCurrentProcessId(),
       timeout_sec);
     fflush(stdout);
   }
}
#endif /* DEBUG_UNHANDLED_EXCEPTION_FILTER */

LONG WINAPI my_unhandler_exception_filter(EXCEPTION_POINTERS *ex_pointers)
{
   static BOOL first_time= TRUE;
   if(!first_time)
   {
     /*
       This routine can be called twice, typically
       when detaching in JIT debugger.
       Return EXCEPTION_EXECUTE_HANDLER to terminate process.
     */
     return EXCEPTION_EXECUTE_HANDLER;
   }
   first_time= FALSE;
#ifdef DEBUG_UNHANDLED_EXCEPTION_FILTER
   /*
    Unfortunately there is no clean way to debug unhandled exception filters,
    as debugger does not stop there(also documented in MSDN)
    To overcome, one could put a MessageBox, but this will not work in service.
    Better solution is to print error message and sleep some minutes
    until debugger is attached
  */
  wait_for_debugger(DEBUGGER_ATTACH_TIMEOUT);
#endif /* DEBUG_UNHANDLED_EXCEPTION_FILTER */
  __try
  {
    my_set_exception_pointers(ex_pointers);
    handle_fatal_signal(ex_pointers->ExceptionRecord->ExceptionCode);
  }
  __except(EXCEPTION_EXECUTE_HANDLER)
  {
    DWORD written;
    const char msg[] = "Got exception in exception handler!\n";
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),msg, sizeof(msg)-1,
      &written,NULL);
  }
  /*
    Return EXCEPTION_CONTINUE_SEARCH to give JIT debugger
    (drwtsn32 or vsjitdebugger) possibility to attach,
    if JIT debugger is configured.
    Windows Error reporting might generate a dump here.
  */
  return EXCEPTION_CONTINUE_SEARCH;
}


void my_init_signals(void)
{
  if(opt_console)
    SetConsoleCtrlHandler(console_event_handler,TRUE);

    /* Avoid MessageBox()es*/
  _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
  _CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDERR);
  _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
  _CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDERR);
  _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
  _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);

   /*
     Do not use SEM_NOGPFAULTERRORBOX in the following SetErrorMode (),
     because it would prevent JIT debugger and Windows error reporting
     from working. We need WER or JIT-debugging, since our own unhandled
     exception filter is not guaranteed to work in all situation
     (like heap corruption or stack overflow)
   */
  SetErrorMode(SetErrorMode(0) | SEM_FAILCRITICALERRORS
                               | SEM_NOOPENFILEERRORBOX);
  SetUnhandledExceptionFilter(my_unhandler_exception_filter);
}

#else // !_WIN32

#ifndef SA_RESETHAND
#define SA_RESETHAND 0
#endif
#ifndef SA_NODEFER
#define SA_NODEFER 0
#endif

void my_init_signals(void)
{
  sigset_t set;
  struct sigaction sa;
  DBUG_ENTER("my_init_signals");

  my_sigset(thr_server_alarm,print_signal_warning); // Should never be called!

  if (!(test_flags & TEST_NO_STACKTRACE) || (test_flags & TEST_CORE_ON_SIGNAL))
  {
    sa.sa_flags = SA_RESETHAND | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sigprocmask(SIG_SETMASK,&sa.sa_mask,NULL);

#ifdef HAVE_STACKTRACE
    my_init_stacktrace();
#endif
    sa.sa_handler=handle_fatal_signal;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
#ifdef SIGBUS
    sigaction(SIGBUS, &sa, NULL);
#endif
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
  }

#ifdef HAVE_GETRLIMIT
  if (test_flags & TEST_CORE_ON_SIGNAL)
  {
    /* Change limits so that we will get a core file */
    struct rlimit rl;
    rl.rlim_cur = rl.rlim_max = RLIM_INFINITY;
    if (setrlimit(RLIMIT_CORE, &rl))
      sql_print_warning("setrlimit could not change the size of core files to 'infinity';  We may not be able to generate a core file on signals");
  }
#endif
  (void) sigemptyset(&set);
  my_sigset(SIGPIPE,SIG_IGN);
  sigaddset(&set,SIGPIPE);
  sigaddset(&set,SIGQUIT);
  sigaddset(&set,SIGHUP);
  sigaddset(&set,SIGTERM);

  /* Fix signals if blocked by parents (can happen on Mac OS X) */
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = print_signal_warning;
  sigaction(SIGTERM, &sa, (struct sigaction*) 0);
  sa.sa_flags = 0;
  sa.sa_handler = print_signal_warning;
  sigaction(SIGHUP, &sa, (struct sigaction*) 0);
#ifdef SIGTSTP
  sigaddset(&set,SIGTSTP);
#endif
  sigaddset(&set,thr_server_alarm);
  if (test_flags & TEST_SIGINT)
    sigdelset(&set,SIGINT);
  else
    sigaddset(&set,SIGINT);
  sigprocmask(SIG_SETMASK,&set,NULL);
  pthread_sigmask(SIG_SETMASK,&set,NULL);
  DBUG_VOID_RETURN;
}


static void start_signal_handler(void)
{
  int error;
  pthread_attr_t thr_attr;
  DBUG_ENTER("start_signal_handler");

  (void) pthread_attr_init(&thr_attr);
  pthread_attr_setscope(&thr_attr,PTHREAD_SCOPE_SYSTEM);
  (void) pthread_attr_setdetachstate(&thr_attr, PTHREAD_CREATE_JOINABLE);

  size_t guardize= 0;
  pthread_attr_getguardsize(&thr_attr, &guardize);

#if defined(__ia64__) || defined(__ia64)
  /*
    Peculiar things with ia64 platforms - it seems we only have half the
    stack size in reality, so we have to double it here
  */
  guardize= my_thread_stack_size;
#endif

  /*
    Set main_thread_id so that SIGTERM/SIGQUIT/SIGKILL can call
    close_connections() successfully.
  */
  main_thread_id= pthread_self();

  pthread_attr_setstacksize(&thr_attr, my_thread_stack_size + guardize);
  mysql_mutex_lock(&LOCK_start_signal_handler);

  if ((error=
       mysql_thread_create(key_thread_signal_hand,
                           &signal_thread_id, &thr_attr, signal_hand, 0)))
  {
    sql_print_error("Can't create interrupt-thread (error %d, errno: %d)",
                    error,errno);
    exit(1);
  }
  mysql_cond_wait(&COND_start_signal_handler, &LOCK_start_signal_handler);
  mysql_mutex_unlock(&LOCK_start_signal_handler);

  (void) pthread_attr_destroy(&thr_attr);
  DBUG_VOID_RETURN;
}


/** This threads handles all signals and alarms. */
/* ARGSUSED */
pthread_handler_t signal_hand(void *arg __attribute__((unused)))
{
  sigset_t set;
  int sig;
  my_thread_init();       // Init new thread

  /*
    Setup alarm handler
    This should actually be '+ max_number_of_slaves' instead of +10,
    but the +10 should be quite safe.
  */
  init_thr_alarm(Connection_handler_manager::max_threads + 10);
  if (test_flags & TEST_SIGINT)
  {
    (void) sigemptyset(&set);     // Setup up SIGINT for debug
    (void) sigaddset(&set,SIGINT);    // For debugging
    (void) pthread_sigmask(SIG_UNBLOCK,&set,NULL);
  }
  (void) sigemptyset(&set);     // Setup up SIGINT for debug
  (void) sigaddset(&set,thr_server_alarm);  // For alarms
  (void) sigaddset(&set,SIGQUIT);
  (void) sigaddset(&set,SIGHUP);
  (void) sigaddset(&set,SIGTERM);
  (void) sigaddset(&set,SIGTSTP);

  /*
    signal to start_signal_handler that we are ready
    This works by waiting for start_signal_handler to free mutex,
    after which we signal it that we are ready.
  */
  mysql_mutex_lock(&LOCK_start_signal_handler);
  mysql_cond_broadcast(&COND_start_signal_handler);
  mysql_mutex_unlock(&LOCK_start_signal_handler);

  /*
    Waiting until mysqld_server_started == true
    to ensure that all server components has been successfully
    initialized. This step is mandatory since signal processing
    could be done safely only when all server components
    has been initialized.
  */
  mysql_mutex_lock(&LOCK_server_started);
  while (!mysqld_server_started)
    mysql_cond_wait(&COND_server_started, &LOCK_server_started);
  mysql_mutex_unlock(&LOCK_server_started);

  for (;;)
  {
    int error;          // Used when debugging
    while ((error= sigwait(&set,&sig)) == EINTR)
    {}
    if (cleanup_done)
    {
      my_thread_end();
      pthread_exit(0);        // Safety
      return 0;               // Avoid compiler warnings
    }
    switch (sig) {
    case SIGTERM:
    case SIGQUIT:
    case SIGKILL:
      /* switch to the file log message processing */
      query_logger.set_handlers((log_output_options != LOG_NONE) ?
                                LOG_FILE : LOG_NONE);
      DBUG_PRINT("info",("Got signal: %d  abort_loop: %d",sig,abort_loop));
      if (!abort_loop)
      {
        abort_loop=1;       // mark abort for threads
#ifdef HAVE_PSI_THREAD_INTERFACE
        /* Delete the instrumentation for the signal thread */
        PSI_THREAD_CALL(delete_current_thread)();
#endif
        close_connections();
        my_thread_end();
        pthread_exit(0);
        return 0;  // Avoid compiler warnings
      }
      break;
    case SIGHUP:
      if (!abort_loop)
      {
        int not_used;
  mysql_print_status();   // Print some debug info
  reload_acl_and_cache((THD*) 0,
           (REFRESH_LOG | REFRESH_TABLES | REFRESH_FAST |
            REFRESH_GRANT |
            REFRESH_THREADS | REFRESH_HOSTS),
           (TABLE_LIST*) 0, &not_used); // Flush logs
      }
      /* reenable query logs after the options were reloaded */
      query_logger.set_handlers(log_output_options);
      break;
    case thr_server_alarm:
      process_alarm(sig);     // Trigger alarms.
      break;
    default:
      break;          /* purecov: tested */
    }
  }
  return(0);          /* purecov: deadcode */
}

#endif // !_WIN32
#endif // !EMBEDDED_LIBRARY


#if BACKTRACE_DEMANGLE
#include <cxxabi.h>
extern "C" char *my_demangle(const char *mangled_name, int *status)
{
  return abi::__cxa_demangle(mangled_name, NULL, NULL, status);
}
#endif


/**
  All global error messages are sent here where the first one is stored
  for the client.
*/
/* ARGSUSED */
extern "C" void my_message_sql(uint error, const char *str, myf MyFlags);

void my_message_sql(uint error, const char *str, myf MyFlags)
{
  THD *thd= current_thd;
  DBUG_ENTER("my_message_sql");
  DBUG_PRINT("error", ("error: %u  message: '%s'", error, str));

  DBUG_ASSERT(str != NULL);
  /*
    An error should have a valid error number (!= 0), so it can be caught
    in stored procedures by SQL exception handlers.
    Calling my_error() with error == 0 is a bug.
    Remaining known places to fix:
    - storage/myisam/mi_create.c, my_printf_error()
    TODO:
    DBUG_ASSERT(error != 0);
  */

  if (error == 0)
  {
    /* At least, prevent new abuse ... */
    DBUG_ASSERT(strncmp(str, "MyISAM table", 12) == 0);
    error= ER_UNKNOWN_ERROR;
  }

  mysql_audit_general(thd, MYSQL_AUDIT_GENERAL_ERROR, error, str);

  if (thd)
  {
    if (MyFlags & ME_FATALERROR)
      thd->is_fatal_error= 1;
    (void) thd->raise_condition(error,
                                NULL,
                                Sql_condition::SL_ERROR,
                                str);
  }

  /* When simulating OOM, skip writing to error log to avoid mtr errors */
  DBUG_EXECUTE_IF("simulate_out_of_memory", DBUG_VOID_RETURN;);

  if (!thd || MyFlags & ME_NOREFRESH)
    sql_print_error("%s: %s",my_progname,str); /* purecov: inspected */
  DBUG_VOID_RETURN;
}


#ifndef EMBEDDED_LIBRARY
extern "C" void *my_str_malloc_mysqld(size_t size);
extern "C" void my_str_free_mysqld(void *ptr);
extern "C" void *my_str_realloc_mysqld(void *ptr, size_t size);

void *my_str_malloc_mysqld(size_t size)
{
  return my_malloc(key_memory_my_str_malloc,
                   size, MYF(MY_FAE));
}


void my_str_free_mysqld(void *ptr)
{
  my_free(ptr);
}

void *my_str_realloc_mysqld(void *ptr, size_t size)
{
  return my_realloc(key_memory_my_str_malloc,
                    ptr, size, MYF(MY_FAE));
}
#endif // !EMBEDDED_LIBRARY

const char *load_default_groups[]= {
#ifdef WITH_NDBCLUSTER_STORAGE_ENGINE
"mysql_cluster",
#endif
"mysqld","server", MYSQL_BASE_VERSION, 0, 0};

#if defined(_WIN32) && !defined(EMBEDDED_LIBRARY)
static const int load_default_groups_sz=
sizeof(load_default_groups)/sizeof(load_default_groups[0]);
#endif

#ifndef EMBEDDED_LIBRARY
/**
  This function is used to check for stack overrun for pathological
  cases of regular expressions and 'like' expressions.
  The call to current_thd is quite expensive, so we try to avoid it
  for the normal cases.
  The size of each stack frame for the wildcmp() routines is ~128 bytes,
  so checking *every* recursive call is not necessary.
 */
extern "C" int
check_enough_stack_size(int recurse_level)
{
  uchar stack_top;
  if (recurse_level % 16 != 0)
    return 0;

  THD *my_thd= current_thd;
  if (my_thd != NULL)
    return check_stack_overrun(my_thd, STACK_MIN_SIZE * 2, &stack_top);
  return 0;
}
#endif


/**
  Initialize one of the global date/time format variables.

  @param format_type    What kind of format should be supported
  @param var_ptr    Pointer to variable that should be updated

  @retval
    0 ok
  @retval
    1 error
*/

static bool init_global_datetime_format(timestamp_type format_type,
                                        DATE_TIME_FORMAT *format)
{
  /*
    Get command line option
    format->format.str is already set by my_getopt
  */
  format->format.length= strlen(format->format.str);

  if (parse_date_time_format(format_type, format))
  {
    my_message_local(ERROR_LEVEL, "Wrong date/time format specifier: %s",
                     format->format.str);
    return true;
  }
  return false;
}

SHOW_VAR com_status_vars[]= {
  {"admin_commands",       (char*) offsetof(STATUS_VAR, com_other), SHOW_LONG_STATUS},
  {"assign_to_keycache",   (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_ASSIGN_TO_KEYCACHE]), SHOW_LONG_STATUS},
  {"alter_db",             (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_ALTER_DB]), SHOW_LONG_STATUS},
  {"alter_db_upgrade",     (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_ALTER_DB_UPGRADE]), SHOW_LONG_STATUS},
  {"alter_event",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_ALTER_EVENT]), SHOW_LONG_STATUS},
  {"alter_function",       (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_ALTER_FUNCTION]), SHOW_LONG_STATUS},
  {"alter_procedure",      (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_ALTER_PROCEDURE]), SHOW_LONG_STATUS},
  {"alter_server",         (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_ALTER_SERVER]), SHOW_LONG_STATUS},
  {"alter_table",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_ALTER_TABLE]), SHOW_LONG_STATUS},
  {"alter_tablespace",     (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_ALTER_TABLESPACE]), SHOW_LONG_STATUS},
  {"alter_user",           (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_ALTER_USER]), SHOW_LONG_STATUS},
  {"analyze",              (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_ANALYZE]), SHOW_LONG_STATUS},
  {"begin",                (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_BEGIN]), SHOW_LONG_STATUS},
  {"binlog",               (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_BINLOG_BASE64_EVENT]), SHOW_LONG_STATUS},
  {"call_procedure",       (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_CALL]), SHOW_LONG_STATUS},
  {"change_db",            (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_CHANGE_DB]), SHOW_LONG_STATUS},
  {"change_master",        (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_CHANGE_MASTER]), SHOW_LONG_STATUS},
  {"change_repl_filter",   (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_CHANGE_REPLICATION_FILTER]), SHOW_LONG_STATUS},
  {"check",                (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_CHECK]), SHOW_LONG_STATUS},
  {"checksum",             (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_CHECKSUM]), SHOW_LONG_STATUS},
  {"commit",               (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_COMMIT]), SHOW_LONG_STATUS},
  {"create_db",            (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_CREATE_DB]), SHOW_LONG_STATUS},
  {"create_event",         (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_CREATE_EVENT]), SHOW_LONG_STATUS},
  {"create_function",      (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_CREATE_SPFUNCTION]), SHOW_LONG_STATUS},
  {"create_index",         (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_CREATE_INDEX]), SHOW_LONG_STATUS},
  {"create_procedure",     (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_CREATE_PROCEDURE]), SHOW_LONG_STATUS},
  {"create_server",        (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_CREATE_SERVER]), SHOW_LONG_STATUS},
  {"create_table",         (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_CREATE_TABLE]), SHOW_LONG_STATUS},
  {"create_trigger",       (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_CREATE_TRIGGER]), SHOW_LONG_STATUS},
  {"create_udf",           (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_CREATE_FUNCTION]), SHOW_LONG_STATUS},
  {"create_user",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_CREATE_USER]), SHOW_LONG_STATUS},
  {"create_view",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_CREATE_VIEW]), SHOW_LONG_STATUS},
  {"dealloc_sql",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_DEALLOCATE_PREPARE]), SHOW_LONG_STATUS},
  {"delete",               (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_DELETE]), SHOW_LONG_STATUS},
  {"delete_multi",         (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_DELETE_MULTI]), SHOW_LONG_STATUS},
  {"do",                   (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_DO]), SHOW_LONG_STATUS},
  {"drop_db",              (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_DROP_DB]), SHOW_LONG_STATUS},
  {"drop_event",           (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_DROP_EVENT]), SHOW_LONG_STATUS},
  {"drop_function",        (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_DROP_FUNCTION]), SHOW_LONG_STATUS},
  {"drop_index",           (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_DROP_INDEX]), SHOW_LONG_STATUS},
  {"drop_procedure",       (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_DROP_PROCEDURE]), SHOW_LONG_STATUS},
  {"drop_server",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_DROP_SERVER]), SHOW_LONG_STATUS},
  {"drop_table",           (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_DROP_TABLE]), SHOW_LONG_STATUS},
  {"drop_trigger",         (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_DROP_TRIGGER]), SHOW_LONG_STATUS},
  {"drop_user",            (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_DROP_USER]), SHOW_LONG_STATUS},
  {"drop_view",            (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_DROP_VIEW]), SHOW_LONG_STATUS},
  {"empty_query",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_EMPTY_QUERY]), SHOW_LONG_STATUS},
  {"execute_sql",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_EXECUTE]), SHOW_LONG_STATUS},
  {"explain_other",        (char*) offsetof(STATUS_VAR, com_stat[(uint)
  SQLCOM_EXPLAIN_OTHER]), SHOW_LONG_STATUS},
  {"flush",                (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_FLUSH]), SHOW_LONG_STATUS},
  {"get_diagnostics",      (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_GET_DIAGNOSTICS]), SHOW_LONG_STATUS},
  {"grant",                (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_GRANT]), SHOW_LONG_STATUS},
  {"ha_close",             (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_HA_CLOSE]), SHOW_LONG_STATUS},
  {"ha_open",              (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_HA_OPEN]), SHOW_LONG_STATUS},
  {"ha_read",              (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_HA_READ]), SHOW_LONG_STATUS},
  {"help",                 (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_HELP]), SHOW_LONG_STATUS},
  {"insert",               (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_INSERT]), SHOW_LONG_STATUS},
  {"insert_select",        (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_INSERT_SELECT]), SHOW_LONG_STATUS},
  {"install_plugin",       (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_INSTALL_PLUGIN]), SHOW_LONG_STATUS},
  {"kill",                 (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_KILL]), SHOW_LONG_STATUS},
  {"load",                 (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_LOAD]), SHOW_LONG_STATUS},
  {"lock_tables",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_LOCK_TABLES]), SHOW_LONG_STATUS},
  {"optimize",             (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_OPTIMIZE]), SHOW_LONG_STATUS},
  {"preload_keys",         (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_PRELOAD_KEYS]), SHOW_LONG_STATUS},
  {"prepare_sql",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_PREPARE]), SHOW_LONG_STATUS},
  {"purge",                (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_PURGE]), SHOW_LONG_STATUS},
  {"purge_before_date",    (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_PURGE_BEFORE]), SHOW_LONG_STATUS},
  {"release_savepoint",    (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_RELEASE_SAVEPOINT]), SHOW_LONG_STATUS},
  {"rename_table",         (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_RENAME_TABLE]), SHOW_LONG_STATUS},
  {"rename_user",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_RENAME_USER]), SHOW_LONG_STATUS},
  {"repair",               (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_REPAIR]), SHOW_LONG_STATUS},
  {"replace",              (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_REPLACE]), SHOW_LONG_STATUS},
  {"replace_select",       (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_REPLACE_SELECT]), SHOW_LONG_STATUS},
  {"reset",                (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_RESET]), SHOW_LONG_STATUS},
  {"resignal",             (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_RESIGNAL]), SHOW_LONG_STATUS},
  {"revoke",               (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_REVOKE]), SHOW_LONG_STATUS},
  {"revoke_all",           (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_REVOKE_ALL]), SHOW_LONG_STATUS},
  {"rollback",             (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_ROLLBACK]), SHOW_LONG_STATUS},
  {"rollback_to_savepoint",(char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_ROLLBACK_TO_SAVEPOINT]), SHOW_LONG_STATUS},
  {"savepoint",            (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SAVEPOINT]), SHOW_LONG_STATUS},
  {"select",               (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SELECT]), SHOW_LONG_STATUS},
  {"set_option",           (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SET_OPTION]), SHOW_LONG_STATUS},
  {"signal",               (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SIGNAL]), SHOW_LONG_STATUS},
  {"show_binlog_events",   (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_BINLOG_EVENTS]), SHOW_LONG_STATUS},
  {"show_binlogs",         (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_BINLOGS]), SHOW_LONG_STATUS},
  {"show_charsets",        (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_CHARSETS]), SHOW_LONG_STATUS},
  {"show_collations",      (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_COLLATIONS]), SHOW_LONG_STATUS},
  {"show_create_db",       (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_CREATE_DB]), SHOW_LONG_STATUS},
  {"show_create_event",    (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_CREATE_EVENT]), SHOW_LONG_STATUS},
  {"show_create_func",     (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_CREATE_FUNC]), SHOW_LONG_STATUS},
  {"show_create_proc",     (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_CREATE_PROC]), SHOW_LONG_STATUS},
  {"show_create_table",    (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_CREATE]), SHOW_LONG_STATUS},
  {"show_create_trigger",  (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_CREATE_TRIGGER]), SHOW_LONG_STATUS},
  {"show_databases",       (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_DATABASES]), SHOW_LONG_STATUS},
  {"show_engine_logs",     (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_ENGINE_LOGS]), SHOW_LONG_STATUS},
  {"show_engine_mutex",    (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_ENGINE_MUTEX]), SHOW_LONG_STATUS},
  {"show_engine_status",   (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_ENGINE_STATUS]), SHOW_LONG_STATUS},
  {"show_events",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_EVENTS]), SHOW_LONG_STATUS},
  {"show_errors",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_ERRORS]), SHOW_LONG_STATUS},
  {"show_fields",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_FIELDS]), SHOW_LONG_STATUS},
  {"show_function_code",   (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_FUNC_CODE]), SHOW_LONG_STATUS},
  {"show_function_status", (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_STATUS_FUNC]), SHOW_LONG_STATUS},
  {"show_grants",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_GRANTS]), SHOW_LONG_STATUS},
  {"show_keys",            (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_KEYS]), SHOW_LONG_STATUS},
  {"show_master_status",   (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_MASTER_STAT]), SHOW_LONG_STATUS},
  {"show_open_tables",     (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_OPEN_TABLES]), SHOW_LONG_STATUS},
  {"show_plugins",         (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_PLUGINS]), SHOW_LONG_STATUS},
  {"show_privileges",      (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_PRIVILEGES]), SHOW_LONG_STATUS},
  {"show_procedure_code",  (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_PROC_CODE]), SHOW_LONG_STATUS},
  {"show_procedure_status",(char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_STATUS_PROC]), SHOW_LONG_STATUS},
  {"show_processlist",     (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_PROCESSLIST]), SHOW_LONG_STATUS},
  {"show_profile",         (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_PROFILE]), SHOW_LONG_STATUS},
  {"show_profiles",        (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_PROFILES]), SHOW_LONG_STATUS},
  {"show_relaylog_events", (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_RELAYLOG_EVENTS]), SHOW_LONG_STATUS},
  {"show_slave_hosts",     (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_SLAVE_HOSTS]), SHOW_LONG_STATUS},
  {"show_slave_status",    (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_SLAVE_STAT]), SHOW_LONG_STATUS},
  {"show_slave_status_nonblocking",    (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_SLAVE_STAT_NONBLOCKING]), SHOW_LONG_STATUS},
  {"show_status",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_STATUS]), SHOW_LONG_STATUS},
  {"show_storage_engines", (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_STORAGE_ENGINES]), SHOW_LONG_STATUS},
  {"show_table_status",    (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_TABLE_STATUS]), SHOW_LONG_STATUS},
  {"show_tables",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_TABLES]), SHOW_LONG_STATUS},
  {"show_triggers",        (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_TRIGGERS]), SHOW_LONG_STATUS},
  {"show_variables",       (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_VARIABLES]), SHOW_LONG_STATUS},
  {"show_warnings",        (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SHOW_WARNS]), SHOW_LONG_STATUS},
  {"slave_start",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SLAVE_START]), SHOW_LONG_STATUS},
  {"slave_stop",           (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_SLAVE_STOP]), SHOW_LONG_STATUS},
  {"stmt_close",           (char*) offsetof(STATUS_VAR, com_stmt_close), SHOW_LONG_STATUS},
  {"stmt_execute",         (char*) offsetof(STATUS_VAR, com_stmt_execute), SHOW_LONG_STATUS},
  {"stmt_fetch",           (char*) offsetof(STATUS_VAR, com_stmt_fetch), SHOW_LONG_STATUS},
  {"stmt_prepare",         (char*) offsetof(STATUS_VAR, com_stmt_prepare), SHOW_LONG_STATUS},
  {"stmt_reprepare",       (char*) offsetof(STATUS_VAR, com_stmt_reprepare), SHOW_LONG_STATUS},
  {"stmt_reset",           (char*) offsetof(STATUS_VAR, com_stmt_reset), SHOW_LONG_STATUS},
  {"stmt_send_long_data",  (char*) offsetof(STATUS_VAR, com_stmt_send_long_data), SHOW_LONG_STATUS},
  {"truncate",             (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_TRUNCATE]), SHOW_LONG_STATUS},
  {"uninstall_plugin",     (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_UNINSTALL_PLUGIN]), SHOW_LONG_STATUS},
  {"unlock_tables",        (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_UNLOCK_TABLES]), SHOW_LONG_STATUS},
  {"update",               (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_UPDATE]), SHOW_LONG_STATUS},
  {"update_multi",         (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_UPDATE_MULTI]), SHOW_LONG_STATUS},
  {"xa_commit",            (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_XA_COMMIT]),SHOW_LONG_STATUS},
  {"xa_end",               (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_XA_END]),SHOW_LONG_STATUS},
  {"xa_prepare",           (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_XA_PREPARE]),SHOW_LONG_STATUS},
  {"xa_recover",           (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_XA_RECOVER]),SHOW_LONG_STATUS},
  {"xa_rollback",          (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_XA_ROLLBACK]),SHOW_LONG_STATUS},
  {"xa_start",             (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_XA_START]),SHOW_LONG_STATUS},
  {NullS, NullS, SHOW_LONG}
};


#ifndef EMBEDDED_LIBRARY
LEX_CSTRING sql_statement_names[(uint) SQLCOM_END + 1];

static void init_sql_statement_names()
{
  static LEX_CSTRING empty= { C_STRING_WITH_LEN("") };

  char *first_com= (char*) offsetof(STATUS_VAR, com_stat[0]);
  char *last_com= (char*) offsetof(STATUS_VAR, com_stat[(uint) SQLCOM_END]);
  int record_size= (char*) offsetof(STATUS_VAR, com_stat[1])
                   - (char*) offsetof(STATUS_VAR, com_stat[0]);
  char *ptr;
  uint i;
  uint com_index;

  for (i= 0; i < ((uint) SQLCOM_END + 1); i++)
    sql_statement_names[i]= empty;

  SHOW_VAR *var= &com_status_vars[0];
  while (var->name != NULL)
  {
    ptr= var->value;
    if ((first_com <= ptr) && (ptr <= last_com))
    {
      com_index= ((int)(ptr - first_com))/record_size;
      DBUG_ASSERT(com_index < (uint) SQLCOM_END);
      sql_statement_names[com_index].str= var->name;
      /* TODO: Change SHOW_VAR::name to a LEX_STRING, to avoid strlen() */
      sql_statement_names[com_index].length= strlen(var->name);
    }
    var++;
  }

  DBUG_ASSERT(strcmp(sql_statement_names[(uint) SQLCOM_SELECT].str, "select") == 0);
  DBUG_ASSERT(strcmp(sql_statement_names[(uint) SQLCOM_SIGNAL].str, "signal") == 0);

  sql_statement_names[(uint) SQLCOM_END].str= "error";
}
#endif // !EMBEDDED_LIBRARY

#ifdef HAVE_PSI_STATEMENT_INTERFACE
PSI_statement_info sql_statement_info[(uint) SQLCOM_END + 1];
PSI_statement_info com_statement_info[(uint) COM_END + 1];

/**
  Initialize the command names array.
  Since we do not want to maintain a separate array,
  this is populated from data mined in com_status_vars,
  which already has one name for each command.
*/
void init_sql_statement_info()
{
  uint i;

  for (i= 0; i < ((uint) SQLCOM_END + 1); i++)
  {
    sql_statement_info[i].m_name= sql_statement_names[i].str;
    sql_statement_info[i].m_flags= 0;
  }

  /* "statement/sql/error" represents broken queries (syntax error). */
  sql_statement_info[(uint) SQLCOM_END].m_name= "error";
  sql_statement_info[(uint) SQLCOM_END].m_flags= 0;
}

void init_com_statement_info()
{
  uint index;

  for (index= 0; index < (uint) COM_END + 1; index++)
  {
    com_statement_info[index].m_name= command_name[index].str;
    com_statement_info[index].m_flags= 0;
  }

  /* "statement/abstract/query" can mutate into "statement/sql/..." */
  com_statement_info[(uint) COM_QUERY].m_flags= PSI_FLAG_MUTABLE;
}
#endif

/**
  Create a replication file name or base for file names.

  @param[in] opt Value of option, or NULL
  @param[in] def Default value if option value is not set.
  @param[in] ext Extension to use for the path

  @returns Pointer to string containing the full file path, or NULL if
  it was not possible to create the path.
 */
static inline const char *
rpl_make_log_name(PSI_memory_key key,
                  const char *opt,
                  const char *def,
                  const char *ext)
{
  DBUG_ENTER("rpl_make_log_name");
  DBUG_PRINT("enter", ("opt: %s, def: %s, ext: %s", opt, def, ext));
  char buff[FN_REFLEN];
  /*
    opt[0] needs to be checked to make sure opt name is not an empty
    string, incase it is an empty string default name will be considered
  */
  const char *base= (opt && opt[0]) ? opt : def;
  unsigned int options=
    MY_REPLACE_EXT | MY_UNPACK_FILENAME | MY_SAFE_PATH;

  /* mysql_real_data_home_ptr  may be null if no value of datadir has been
     specified through command-line or througha cnf file. If that is the 
     case we make mysql_real_data_home_ptr point to mysql_real_data_home
     which, in that case holds the default path for data-dir.
  */ 
  if(mysql_real_data_home_ptr == NULL)
    mysql_real_data_home_ptr= mysql_real_data_home;

  if (fn_format(buff, base, mysql_real_data_home_ptr, ext, options))
    DBUG_RETURN(my_strdup(key, buff, MYF(0)));
  else
    DBUG_RETURN(NULL);
}


int init_common_variables()
{
  umask(((~my_umask) & 0666));
  my_decimal_set_zero(&decimal_zero); // set decimal_zero constant;
  tzset();      // Set tzname

  max_system_variables.pseudo_thread_id= (ulong)~0;
  server_start_time= flush_status_time= my_time(0);

  rpl_filter= new Rpl_filter;
  binlog_filter= new Rpl_filter;
  if (!rpl_filter || !binlog_filter)
  {
    sql_print_error("Could not allocate replication and binlog filters: %s",
                    strerror(errno));
    return 1;
  }

  if (init_thread_environment() ||
      mysql_init_variables())
    return 1;

  if (ignore_db_dirs_init())
    return 1;

  {
    struct tm tm_tmp;
    localtime_r(&server_start_time,&tm_tmp);
    strmake(system_time_zone, tzname[tm_tmp.tm_isdst != 0 ? 1 : 0],
            sizeof(system_time_zone)-1);

 }

  /*
    We set SYSTEM time zone as reasonable default and
    also for failure of my_tz_init() and bootstrap mode.
    If user explicitly set time zone with --default-time-zone
    option we will change this value in my_tz_init().
  */
  global_system_variables.time_zone= my_tz_SYSTEM;

#ifdef HAVE_PSI_INTERFACE
  /*
    Complete the mysql_bin_log initialization.
    Instrumentation keys are known only after the performance schema initialization,
    and can not be set in the MYSQL_BIN_LOG constructor (called before main()).
  */
  mysql_bin_log.set_psi_keys(key_BINLOG_LOCK_index,
                             key_BINLOG_LOCK_commit,
                             key_BINLOG_LOCK_commit_queue,
                             key_BINLOG_LOCK_done,
                             key_BINLOG_LOCK_flush_queue,
                             key_BINLOG_LOCK_log,
                             key_BINLOG_LOCK_binlog_end_pos,
                             key_BINLOG_LOCK_sync,
                             key_BINLOG_LOCK_sync_queue,
                             key_BINLOG_LOCK_xids,
                             key_BINLOG_COND_done,
                             key_BINLOG_update_cond,
                             key_BINLOG_prep_xids_cond,
                             key_file_binlog,
                             key_file_binlog_index);
#endif

  /*
    Init mutexes for the global MYSQL_BIN_LOG objects.
    As safe_mutex depends on what MY_INIT() does, we can't init the mutexes of
    global MYSQL_BIN_LOGs in their constructors, because then they would be
    inited before MY_INIT(). So we do it here.
  */
  mysql_bin_log.init_pthread_objects();

  /* TODO: remove this when my_time_t is 64 bit compatible */
  if (!IS_TIME_T_VALID_FOR_TIMESTAMP(server_start_time))
  {
    sql_print_error("This MySQL server doesn't support dates later then 2038");
    return 1;
  }

  if (gethostname(glob_hostname,sizeof(glob_hostname)) < 0)
  {
    strmake(glob_hostname, STRING_WITH_LEN("localhost"));
    sql_print_warning("gethostname failed, using '%s' as hostname",
                      glob_hostname);
    strmake(default_logfile_name, STRING_WITH_LEN("mysql"));
  }
  else
    strmake(default_logfile_name, glob_hostname,
      sizeof(default_logfile_name)-5);

  strmake(pidfile_name, default_logfile_name, sizeof(pidfile_name)-5);
  my_stpcpy(fn_ext(pidfile_name),".pid");    // Add proper extension


  /*
    The default-storage-engine entry in my_long_options should have a
    non-null default value. It was earlier intialized as
    (longlong)"MyISAM" in my_long_options but this triggered a
    compiler error in the Sun Studio 12 compiler. As a work-around we
    set the def_value member to 0 in my_long_options and initialize it
    to the correct value here.

    From MySQL 5.5 onwards, the default storage engine is InnoDB
    (except in the embedded server, where the default continues to
    be MyISAM)
  */
#ifdef EMBEDDED_LIBRARY
  default_storage_engine= const_cast<char *>("MyISAM");
#else
  default_storage_engine= const_cast<char *>("InnoDB");
#endif
  default_tmp_storage_engine= default_storage_engine;


  /*
    Add server status variables to the dynamic list of
    status variables that is shown by SHOW STATUS.
    Later, in plugin_init, and mysql_install_plugin
    new entries could be added to that list.
  */
  if (add_status_vars(status_vars))
    return 1; // an error was already reported

#ifndef DBUG_OFF
  /*
    We have few debug-only commands in com_status_vars, only visible in debug
    builds. for simplicity we enable the assert only in debug builds

    There are 8 Com_ variables which don't have corresponding SQLCOM_ values:
    (TODO strictly speaking they shouldn't be here, should not have Com_ prefix
    that is. Perhaps Stmt_ ? Comstmt_ ? Prepstmt_ ?)

      Com_admin_commands       => com_other
      Com_stmt_close           => com_stmt_close
      Com_stmt_execute         => com_stmt_execute
      Com_stmt_fetch           => com_stmt_fetch
      Com_stmt_prepare         => com_stmt_prepare
      Com_stmt_reprepare       => com_stmt_reprepare
      Com_stmt_reset           => com_stmt_reset
      Com_stmt_send_long_data  => com_stmt_send_long_data

    With this correction the number of Com_ variables (number of elements in
    the array, excluding the last element - terminator) must match the number
    of SQLCOM_ constants.
  */
  compile_time_assert(sizeof(com_status_vars)/sizeof(com_status_vars[0]) - 1 ==
                     SQLCOM_END + 8);
#endif

  if (get_options(&remaining_argc, &remaining_argv))
    return 1;

  if (set_default_auth_plugin(default_auth_plugin, strlen(default_auth_plugin)))
  {
    sql_print_error("Can't start server: "
		    "Invalid value for --default-authentication-plugin");
    return 1;
  }
  set_server_version();

  log_warnings= log_error_verbosity - 1; // backward compatibility

  sql_print_information("%s (mysqld %s) starting as process %lu ...",
                        my_progname, server_version, (ulong) getpid());


#ifndef EMBEDDED_LIBRARY
  if (opt_help && !opt_verbose)
    unireg_abort(0);
#endif /*!EMBEDDED_LIBRARY*/

  DBUG_PRINT("info",("%s  Ver %s for %s on %s\n",my_progname,
         server_version, SYSTEM_TYPE,MACHINE_TYPE));

#ifdef HAVE_LINUX_LARGE_PAGES
  /* Initialize large page size */
  if (opt_large_pages && (opt_large_page_size= my_get_large_page_size()))
  {
      DBUG_PRINT("info", ("Large page set, large_page_size = %d",
                 opt_large_page_size));
      my_use_large_pages= 1;
      my_large_page_size= opt_large_page_size;
  }
  else
  {
    opt_large_pages= 0;
    /*
       Either not configured to use large pages or Linux haven't
       been compiled with large page support
    */
  }
#endif /* HAVE_LINUX_LARGE_PAGES */
#ifdef HAVE_SOLARIS_LARGE_PAGES
#define LARGE_PAGESIZE (4*1024*1024)  /* 4MB */
#define SUPER_LARGE_PAGESIZE (256*1024*1024)  /* 256MB */
  if (opt_large_pages)
  {
  /*
    tell the kernel that we want to use 4/256MB page for heap storage
    and also for the stack. We use 4 MByte as default and if the
    super-large-page is set we increase it to 256 MByte. 256 MByte
    is for server installations with GBytes of RAM memory where
    the MySQL Server will have page caches and other memory regions
    measured in a number of GBytes.
    We use as big pages as possible which isn't bigger than the above
    desired page sizes.
  */
   int nelem;
   size_t max_desired_page_size;
   if (opt_super_large_pages)
     max_desired_page_size= SUPER_LARGE_PAGESIZE;
   else
     max_desired_page_size= LARGE_PAGESIZE;
   nelem = getpagesizes(NULL, 0);
   if (nelem > 0)
   {
     size_t *pagesize = (size_t *) malloc(sizeof(size_t) * nelem);
     if (pagesize != NULL && getpagesizes(pagesize, nelem) > 0)
     {
       size_t max_page_size= 0;
       for (int i= 0; i < nelem; i++)
       {
         if (pagesize[i] > max_page_size &&
             pagesize[i] <= max_desired_page_size)
            max_page_size= pagesize[i];
       }
       free(pagesize);
       if (max_page_size > 0)
       {
         struct memcntl_mha mpss;

         mpss.mha_cmd= MHA_MAPSIZE_BSSBRK;
         mpss.mha_pagesize= max_page_size;
         mpss.mha_flags= 0;
         memcntl(NULL, 0, MC_HAT_ADVISE, (caddr_t)&mpss, 0, 0);
         mpss.mha_cmd= MHA_MAPSIZE_STACK;
         memcntl(NULL, 0, MC_HAT_ADVISE, (caddr_t)&mpss, 0, 0);
       }
     }
   }
  }
#endif /* HAVE_SOLARIS_LARGE_PAGES */

  longlong default_value;
  sys_var *var;
#ifndef EMBEDDED_LIBRARY
  /* Calculate and update default value for thread_cache_size. */
  if ((default_value= 8 + max_connections / 100) > 100)
    default_value= 100;
  var= intern_find_sys_var(STRING_WITH_LEN("thread_cache_size"));
  var->update_default(default_value);
#endif

  /* Calculate and update default value for host_cache_size. */
  if ((default_value= 128 + max_connections) > 628 &&
      (default_value= 628 + ((max_connections - 500) / 20)) > 2000)
    default_value= 2000;
  var= intern_find_sys_var(STRING_WITH_LEN("host_cache_size"));
  var->update_default(default_value);

#ifndef EMBEDDED_LIBRARY
  /* Fix thread_cache_size. */
  if (!thread_cache_size_specified &&
      (Per_thread_connection_handler::max_blocked_pthreads=
       8 + max_connections / 100) > 100)
    Per_thread_connection_handler::max_blocked_pthreads= 100;
#endif // !EMBEDDED_LIBRARY

  /* Fix host_cache_size. */
  if (!host_cache_size_specified &&
      (host_cache_size= 128 + max_connections) > 628 &&
      (host_cache_size= 628 + ((max_connections - 500) / 20)) > 2000)
    host_cache_size= 2000;

  /* Fix back_log */
  if (back_log == 0 && (back_log= 50 + max_connections / 5) > 900)
    back_log= 900;

  unireg_init(opt_specialflag); /* Set up extern variabels */
  if (!(my_default_lc_messages=
        my_locale_by_name(lc_messages)))
  {
    sql_print_error("Unknown locale: '%s'", lc_messages);
    return 1;
  }
  global_system_variables.lc_messages= my_default_lc_messages;
  if (init_errmessage())  /* Read error messages from file */
    return 1;
  init_client_errs();
  mysql_client_plugin_init();
  lex_init();
  if (item_create_init())
    return 1;
  item_init();
#ifndef EMBEDDED_LIBRARY
  my_regex_init(&my_charset_latin1, check_enough_stack_size);
  my_string_stack_guard= check_enough_stack_size;
#else
  my_regex_init(&my_charset_latin1, NULL);
#endif
  /*
    Process a comma-separated character set list and choose
    the first available character set. This is mostly for
    test purposes, to be able to start "mysqld" even if
    the requested character set is not available (see bug#18743).
  */
  for (;;)
  {
    char *next_character_set_name= strchr(default_character_set_name, ',');
    if (next_character_set_name)
      *next_character_set_name++= '\0';
    if (!(default_charset_info=
          get_charset_by_csname(default_character_set_name,
                                MY_CS_PRIMARY, MYF(MY_WME))))
    {
      if (next_character_set_name)
      {
        default_character_set_name= next_character_set_name;
        default_collation_name= 0;          // Ignore collation
      }
      else
        return 1;                           // Eof of the list
    }
    else
      break;
  }

  if (default_collation_name)
  {
    CHARSET_INFO *default_collation;
    default_collation= get_charset_by_name(default_collation_name, MYF(0));
    if (!default_collation)
    {
#ifdef WITH_PERFSCHEMA_STORAGE_ENGINE
      buffered_logs.print();
      buffered_logs.cleanup();
#endif
      sql_print_error(ER_DEFAULT(ER_UNKNOWN_COLLATION), default_collation_name);
      return 1;
    }
    if (!my_charset_same(default_charset_info, default_collation))
    {
      sql_print_error(ER_DEFAULT(ER_COLLATION_CHARSET_MISMATCH),
          default_collation_name,
          default_charset_info->csname);
      return 1;
    }
    default_charset_info= default_collation;
  }
  /* Set collactions that depends on the default collation */
  global_system_variables.collation_server=  default_charset_info;
  global_system_variables.collation_database=  default_charset_info;

  if (is_supported_parser_charset(default_charset_info))
  {
    global_system_variables.collation_connection= default_charset_info;
    global_system_variables.character_set_results= default_charset_info;
    global_system_variables.character_set_client= default_charset_info;
  }
  else
  {
    sql_print_information("'%s' can not be used as client character set. "
                          "'%s' will be used as default client character set.",
                          default_charset_info->csname,
                          my_charset_latin1.csname);
    global_system_variables.collation_connection= &my_charset_latin1;
    global_system_variables.character_set_results= &my_charset_latin1;
    global_system_variables.character_set_client= &my_charset_latin1;
  }

  if (!(character_set_filesystem=
        get_charset_by_csname(character_set_filesystem_name,
                              MY_CS_PRIMARY, MYF(MY_WME))))
    return 1;
  global_system_variables.character_set_filesystem= character_set_filesystem;

  if (!(my_default_lc_time_names=
        my_locale_by_name(lc_time_names_name)))
  {
    sql_print_error("Unknown locale: '%s'", lc_time_names_name);
    return 1;
  }
  global_system_variables.lc_time_names= my_default_lc_time_names;

  /* check log options and issue warnings if needed */
  if (opt_general_log && opt_general_logname && !(log_output_options & LOG_FILE) &&
      !(log_output_options & LOG_NONE))
    sql_print_warning("Although a path was specified for the "
                      "--general-log-file option, log tables are used. "
                      "To enable logging to files use the --log-output=file option.");

  if (opt_slow_log && opt_slow_logname && !(log_output_options & LOG_FILE)
      && !(log_output_options & LOG_NONE))
    sql_print_warning("Although a path was specified for the "
                      "--slow-query-log-file option, log tables are used. "
                      "To enable logging to files use the --log-output=file option.");

#define FIX_LOG_VAR(VAR, ALT)                                   \
  if (!VAR || !*VAR)                                            \
    VAR= ALT;

  FIX_LOG_VAR(opt_general_logname,
              make_query_log_name(logname_path, QUERY_LOG_GENERAL));
  FIX_LOG_VAR(opt_slow_logname,
              make_query_log_name(slow_logname_path, QUERY_LOG_SLOW));

#if defined(ENABLED_DEBUG_SYNC)
  /* Initialize the debug sync facility. See debug_sync.cc. */
  if (debug_sync_init())
    return 1; /* purecov: tested */
#endif /* defined(ENABLED_DEBUG_SYNC) */

#if defined(__linux__)
  if (use_temp_pool && bitmap_init(&temp_pool,0,1024,1))
    return 1;
#else
  use_temp_pool= 0;
#endif

  if (my_dboptions_cache_init())
    return 1;

  /*
    Ensure that lower_case_table_names is set on system where we have case
    insensitive names.  If this is not done the users MyISAM tables will
    get corrupted if accesses with names of different case.
  */
  DBUG_PRINT("info", ("lower_case_table_names: %d", lower_case_table_names));
  lower_case_file_system= test_if_case_insensitive(mysql_real_data_home);
  if (!lower_case_table_names && lower_case_file_system == 1)
  {
    if (lower_case_table_names_used)
    {
      sql_print_warning("\
You have forced lower_case_table_names to 0 through a command-line \
option, even though your file system '%s' is case insensitive.  This means \
that you can corrupt a MyISAM table by accessing it with different cases. \
You should consider changing lower_case_table_names to 1 or 2",
      mysql_real_data_home);
    }
    else
    {
      sql_print_warning("Setting lower_case_table_names=2 because file system for %s is case insensitive", mysql_real_data_home);
      lower_case_table_names= 2;
    }
  }
  else if (lower_case_table_names == 2 &&
           !(lower_case_file_system=
             (test_if_case_insensitive(mysql_real_data_home) == 1)))
  {
    sql_print_warning("lower_case_table_names was set to 2, even though your "
                        "the file system '%s' is case sensitive.  Now setting "
                        "lower_case_table_names to 0 to avoid future problems.",
      mysql_real_data_home);
    lower_case_table_names= 0;
  }
  else
  {
    lower_case_file_system=
      (test_if_case_insensitive(mysql_real_data_home) == 1);
  }

  /* Reset table_alias_charset, now that lower_case_table_names is set. */
  table_alias_charset= (lower_case_table_names ?
      &my_charset_utf8_tolower_ci :
      &my_charset_bin);

  /*
    Build do_table and ignore_table rules to hush
    after the resetting of table_alias_charset
  */
  if (rpl_filter->build_do_table_hash() ||
      rpl_filter->build_ignore_table_hash())
  {
    sql_print_error("An error occurred while building do_table"
                    "and ignore_table rules to hush.");
    return 1;
  }

  if (ignore_db_dirs_process_additions())
  {
    sql_print_error("An error occurred while storing ignore_db_dirs to a hash.");
    return 1;
  }

  return 0;
}


static int init_thread_environment()
{
  mysql_mutex_init(key_LOCK_status, &LOCK_status, MY_MUTEX_INIT_FAST);
  mysql_mutex_init(key_LOCK_manager,
                   &LOCK_manager, MY_MUTEX_INIT_FAST);
  mysql_mutex_init(key_LOCK_crypt, &LOCK_crypt, MY_MUTEX_INIT_FAST);
  mysql_mutex_init(key_LOCK_user_conn, &LOCK_user_conn, MY_MUTEX_INIT_FAST);
  mysql_mutex_init(key_LOCK_active_mi, &LOCK_active_mi, MY_MUTEX_INIT_FAST);
  mysql_mutex_init(key_LOCK_global_system_variables,
                   &LOCK_global_system_variables, MY_MUTEX_INIT_FAST);
  mysql_rwlock_init(key_rwlock_LOCK_system_variables_hash,
                    &LOCK_system_variables_hash);
  mysql_mutex_init(key_LOCK_prepared_stmt_count,
                   &LOCK_prepared_stmt_count, MY_MUTEX_INIT_FAST);
  mysql_mutex_init(key_LOCK_sql_slave_skip_counter,
                   &LOCK_sql_slave_skip_counter, MY_MUTEX_INIT_FAST);
  mysql_mutex_init(key_LOCK_slave_net_timeout,
                   &LOCK_slave_net_timeout, MY_MUTEX_INIT_FAST);
  mysql_mutex_init(key_LOCK_error_messages,
                   &LOCK_error_messages, MY_MUTEX_INIT_FAST);
  mysql_mutex_init(key_LOCK_uuid_generator,
                   &LOCK_uuid_generator, MY_MUTEX_INIT_FAST);
  mysql_mutex_init(key_LOCK_sql_rand,
                   &LOCK_sql_rand, MY_MUTEX_INIT_FAST);
  mysql_mutex_init(key_LOCK_log_throttle_qni,
                   &LOCK_log_throttle_qni, MY_MUTEX_INIT_FAST);
#ifdef HAVE_OPENSSL
  mysql_mutex_init(key_LOCK_des_key_file,
                   &LOCK_des_key_file, MY_MUTEX_INIT_FAST);
#ifndef HAVE_YASSL
  openssl_stdlocks= (openssl_lock_t*) OPENSSL_malloc(CRYPTO_num_locks() *
                                                     sizeof(openssl_lock_t));
  for (int i= 0; i < CRYPTO_num_locks(); ++i)
    mysql_rwlock_init(key_rwlock_openssl, &openssl_stdlocks[i].lock);
  CRYPTO_set_dynlock_create_callback(openssl_dynlock_create);
  CRYPTO_set_dynlock_destroy_callback(openssl_dynlock_destroy);
  CRYPTO_set_dynlock_lock_callback(openssl_lock);
  CRYPTO_set_locking_callback(openssl_lock_function);
  CRYPTO_set_id_callback(openssl_id_function);
#endif
#endif
  mysql_rwlock_init(key_rwlock_LOCK_sys_init_connect, &LOCK_sys_init_connect);
  mysql_rwlock_init(key_rwlock_LOCK_sys_init_slave, &LOCK_sys_init_slave);
  mysql_rwlock_init(key_rwlock_LOCK_grant, &LOCK_grant);
  mysql_cond_init(key_COND_manager, &COND_manager, NULL);
  mysql_mutex_init(key_LOCK_server_started,
                   &LOCK_server_started, MY_MUTEX_INIT_FAST);
  mysql_cond_init(key_COND_server_started, &COND_server_started, NULL);
  sp_cache_init();
#ifndef EMBEDDED_LIBRARY
  Events::init_mutexes();
#if defined(_WIN32)
  mysql_mutex_init(key_LOCK_handler_count,
                   &LOCK_handler_count, MY_MUTEX_INIT_FAST);
  mysql_cond_init(key_COND_handler_count, &COND_handler_count, NULL);
#else
  mysql_mutex_init(key_LOCK_socket_listener_active,
                   &LOCK_socket_listener_active, MY_MUTEX_INIT_FAST);
  mysql_cond_init(key_COND_socket_listener_active,
                  &COND_socket_listener_active, NULL);
  mysql_mutex_init(key_LOCK_start_signal_handler,
                   &LOCK_start_signal_handler, MY_MUTEX_INIT_FAST);
  mysql_cond_init(key_COND_start_signal_handler,
                  &COND_start_signal_handler, NULL);
#endif // _WIN32
#endif // !EMBEDDED_LIBRARY
  /* Parameter for threads created for connections */
  (void) pthread_attr_init(&connection_attrib);
  (void) pthread_attr_setdetachstate(&connection_attrib,
             PTHREAD_CREATE_DETACHED);
  pthread_attr_setscope(&connection_attrib, PTHREAD_SCOPE_SYSTEM);

  DBUG_ASSERT(! THR_THD_initialized);
  DBUG_ASSERT(! THR_MALLOC_initialized);
  if (pthread_key_create(&THR_THD,NULL) ||
      pthread_key_create(&THR_MALLOC,NULL))
  {
    sql_print_error("Can't create thread-keys");
    return 1;
  }
  THR_THD_initialized= true;
  THR_MALLOC_initialized= true;
  return 0;
}


#if defined(HAVE_OPENSSL) && !defined(HAVE_YASSL)
static unsigned long openssl_id_function()
{
  return (unsigned long) pthread_self();
}


static openssl_lock_t *openssl_dynlock_create(const char *file, int line)
{
  openssl_lock_t *lock= new openssl_lock_t;
  mysql_rwlock_init(key_rwlock_openssl, &lock->lock);
  return lock;
}


static void openssl_dynlock_destroy(openssl_lock_t *lock, const char *file,
            int line)
{
  mysql_rwlock_destroy(&lock->lock);
  delete lock;
}


static void openssl_lock_function(int mode, int n, const char *file, int line)
{
  if (n < 0 || n > CRYPTO_num_locks())
  {
    /* Lock number out of bounds. */
    sql_print_error("Fatal: OpenSSL interface problem (n = %d)", n);
    abort();
  }
  openssl_lock(mode, &openssl_stdlocks[n], file, line);
}


static void openssl_lock(int mode, openssl_lock_t *lock, const char *file,
       int line)
{
  int err;
  char const *what;

  switch (mode) {
  case CRYPTO_LOCK|CRYPTO_READ:
    what = "read lock";
    err= mysql_rwlock_rdlock(&lock->lock);
    break;
  case CRYPTO_LOCK|CRYPTO_WRITE:
    what = "write lock";
    err= mysql_rwlock_wrlock(&lock->lock);
    break;
  case CRYPTO_UNLOCK|CRYPTO_READ:
  case CRYPTO_UNLOCK|CRYPTO_WRITE:
    what = "unlock";
    err= mysql_rwlock_unlock(&lock->lock);
    break;
  default:
    /* Unknown locking mode. */
    sql_print_error("Fatal: OpenSSL interface problem (mode=0x%x)", mode);
    abort();
  }
  if (err)
  {
    sql_print_error("Fatal: can't %s OpenSSL lock", what);
    abort();
  }
}
#endif /* HAVE_OPENSSL */


static int init_ssl()
{
#ifdef HAVE_OPENSSL
#ifndef HAVE_YASSL
  CRYPTO_malloc_init();
#endif
  ssl_start();
#ifndef EMBEDDED_LIBRARY
  if (opt_use_ssl)
  {
    enum enum_ssl_init_error error= SSL_INITERR_NOERROR;

    /* having ssl_acceptor_fd != 0 signals the use of SSL */
    ssl_acceptor_fd= new_VioSSLAcceptorFd(opt_ssl_key, opt_ssl_cert,
					  opt_ssl_ca, opt_ssl_capath,
					  opt_ssl_cipher, &error,
                                          opt_ssl_crl, opt_ssl_crlpath);
    DBUG_PRINT("info",("ssl_acceptor_fd: 0x%lx", (long) ssl_acceptor_fd));
    ERR_remove_state(0);
    if (!ssl_acceptor_fd)
    {
      sql_print_warning("Failed to setup SSL");
      sql_print_warning("SSL error: %s", sslGetErrString(error));
      opt_use_ssl = 0;
      have_ssl= SHOW_OPTION_DISABLED;
    }
  }
  else
  {
    have_ssl= SHOW_OPTION_DISABLED;
  }
#else
  have_ssl= SHOW_OPTION_DISABLED;
#endif /* ! EMBEDDED_LIBRARY */
  if (des_key_file)
    load_des_key_file(des_key_file);
#ifndef HAVE_YASSL
  if (init_rsa_keys())
    return 1;
#endif
#endif /* HAVE_OPENSSL */
  return 0;
}


static void end_ssl()
{
#ifdef HAVE_OPENSSL
#ifndef EMBEDDED_LIBRARY
  if (ssl_acceptor_fd)
  {
    free_vio_ssl_acceptor_fd(ssl_acceptor_fd);
    ssl_acceptor_fd= 0;
  }
#endif /* ! EMBEDDED_LIBRARY */
#ifndef HAVE_YASSL
  deinit_rsa_keys();
#endif
#endif /* HAVE_OPENSSL */
}

/**
  Generate a UUID and save it into server_uuid variable.

  @return Retur 0 or 1 if an error occurred.
 */
static int generate_server_uuid()
{
  THD *thd;
  Item_func_uuid *func_uuid;
  String uuid;

  /*
    To be able to run this from boot, we allocate a temporary THD
   */
  if (!(thd=new THD))
  {
    sql_print_error("Failed to generate a server UUID because it is failed"
                    " to allocate the THD.");
    return 1;
  }
  thd->thread_stack= (char*) &thd;
  thd->store_globals();
  lex_start(thd);
  func_uuid= new (thd->mem_root) Item_func_uuid();
  func_uuid->fixed= 1;
  func_uuid->val_str(&uuid);

  delete thd;

  strncpy(server_uuid, uuid.c_ptr(), UUID_LENGTH);
  server_uuid[UUID_LENGTH]= '\0';
  return 0;
}

/**
  Save all options which was auto-generated by server-self into the given file.

  @param fname The name of the file in which the auto-generated options will b
  e saved.

  @return Return 0 or 1 if an error occurred.
 */
int flush_auto_options(const char* fname)
{
  File fd;
  IO_CACHE io_cache;
  int result= 0;

  if ((fd= my_open((const char *)fname, O_CREAT|O_RDWR, MYF(MY_WME))) < 0)
  {
    sql_print_error("Failed to create file(file: '%s', errno %d)", fname, my_errno);
    return 1;
  }

  if (init_io_cache(&io_cache, fd, IO_SIZE*2, WRITE_CACHE, 0L, 0, MYF(MY_WME)))
  {
    sql_print_error("Failed to create a cache on (file: %s', errno %d)", fname, my_errno);
    my_close(fd, MYF(MY_WME));
    return 1;
  }

  my_b_seek(&io_cache, 0L);
  my_b_printf(&io_cache, "%s\n", "[auto]");
  my_b_printf(&io_cache, "server-uuid=%s\n", server_uuid);

  if (flush_io_cache(&io_cache) || my_sync(fd, MYF(MY_WME)))
    result= 1;

  my_close(fd, MYF(MY_WME));
  end_io_cache(&io_cache);
  return result;
}

/**
  File 'auto.cnf' resides in the data directory to hold values of options that
  server evaluates itself and that needs to be durable to sustain the server
  restart. There is only a section ['auto'] in the file. All these options are
  in the section. Only one option exists now, it is server_uuid.
  Note, the user may not supply any literal value to these auto-options, and
  only allowed to trigger (re)evaluation.
  For instance, 'server_uuid' value will be evaluated and stored if there is
  no corresponding line in the file.
  Because of the specifics of the auto-options, they need a seperate storage.
  Meanwhile, it is the 'auto.cnf' that has the same structure as 'my.cnf'.

  @todo consider to implement sql-query-able persistent storage by WL#5279.
  @return Return 0 or 1 if an error occurred.
 */
static int init_server_auto_options()
{
  bool flush= false;
  char fname[FN_REFLEN];
  char *name= (char *)"auto";
  const char *groups[]= {"auto", NULL};
  char *uuid= 0;
  my_option auto_options[]= {
    {"server-uuid", 0, "", &uuid, &uuid,
      0, GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
    {0, 0, 0, 0, 0, 0, GET_NO_ARG, NO_ARG, 0, 0, 0, 0, 0, 0}
  };

  DBUG_ENTER("init_server_auto_options");

  if (NULL == fn_format(fname, "auto.cnf", mysql_data_home, "",
                        MY_UNPACK_FILENAME | MY_SAFE_PATH))
    DBUG_RETURN(1);

  /* load_defaults require argv[0] is not null */
  char **argv= &name;
  int argc= 1;
  if (!check_file_permissions(fname))
  {
    /*
      Found a world writable file hence removing it as it is dangerous to write
      a new UUID into the same file.
     */
    my_delete(fname,MYF(MY_WME));
    sql_print_warning("World-writable config file '%s' has been removed.\n",
                      fname);
  }

  /* load all options in 'auto.cnf'. */
  if (my_load_defaults(fname, groups, &argc, &argv, NULL))
    DBUG_RETURN(1);

  /*
    Record the origial pointer allocated by my_load_defaults for free,
    because argv will be changed by handle_options
   */
  char **old_argv= argv;
  if (handle_options(&argc, &argv, auto_options, mysqld_get_one_option))
    DBUG_RETURN(1);

  DBUG_PRINT("info", ("uuid=%p=%s server_uuid=%s", uuid, uuid, server_uuid));
  if (uuid)
  {
    if (!Uuid::is_valid(uuid))
    {
      sql_print_error("The server_uuid stored in auto.cnf file is not a valid UUID.");
      goto err;
    }
    strcpy(server_uuid, uuid);
  }
  else
  {
    DBUG_PRINT("info", ("generating server_uuid"));
    flush= TRUE;
    /* server_uuid will be set in the function */
    if (generate_server_uuid())
      goto err;
    DBUG_PRINT("info", ("generated server_uuid=%s", server_uuid));
    sql_print_warning("No existing UUID has been found, so we assume that this"
                      " is the first time that this server has been started."
                      " Generating a new UUID: %s.",
                      server_uuid);
  }
  /*
    The uuid has been copied to server_uuid, so the memory allocated by
    my_load_defaults can be freed now.
   */
  free_defaults(old_argv);

  if (flush)
    DBUG_RETURN(flush_auto_options(fname));
  DBUG_RETURN(0);
err:
  free_defaults(argv);
  DBUG_RETURN(1);
}


static bool
initialize_storage_engine(char *se_name, const char *se_kind,
                          plugin_ref *dest_plugin)
{
  LEX_STRING name= { se_name, strlen(se_name) };
  plugin_ref plugin;
  handlerton *hton;
  if ((plugin= ha_resolve_by_name(0, &name, FALSE)))
    hton= plugin_data(plugin, handlerton*);
  else
  {
    sql_print_error("Unknown/unsupported storage engine: %s", se_name);
    return true;
  }
  if (!ha_storage_engine_is_enabled(hton))
  {
    if (!opt_bootstrap)
    {
      sql_print_error("Default%s storage engine (%s) is not available",
                      se_kind, se_name);
      return true;
    }
    DBUG_ASSERT(*dest_plugin);
  }
  else
  {
    /*
      Need to unlock as global_system_variables.table_plugin
      was acquired during plugin_init()
    */
    plugin_unlock(0, *dest_plugin);
    *dest_plugin= plugin;
  }
  return false;
}


static void init_server_query_cache()
{
  ulong set_cache_size;

  query_cache.set_min_res_unit(query_cache_min_res_unit);
  query_cache.init();
	
  set_cache_size= query_cache.resize(query_cache_size);
  if (set_cache_size != query_cache_size)
  {
    sql_print_warning(ER_DEFAULT(ER_WARN_QC_RESIZE), query_cache_size,
                      set_cache_size);
    query_cache_size= set_cache_size;
  }
}


static int init_server_components()
{
  DBUG_ENTER("init_server_components");
  /*
    We need to call each of these following functions to ensure that
    all things are initialized so that unireg_abort() doesn't fail
  */
  mdl_init();
  if (table_def_init() | hostname_cache_init(host_cache_size))
    unireg_abort(1);

#ifdef HAVE_MY_TIMER
  if (my_timer_initialize())
    sql_print_error("Failed to initialize timer component (errno %d).", errno);
  else
    have_statement_timeout= SHOW_OPTION_YES;
#else
  have_statement_timeout= SHOW_OPTION_NO;
#endif


  init_server_query_cache();

  randominit(&sql_rand,(ulong) server_start_time,(ulong) server_start_time/2);
  setup_fpu();
  init_thr_lock();
#ifdef HAVE_REPLICATION
  init_slave_list();
#endif

  /* Setup logs */

  /*
    Enable old-fashioned error log, except when the user has requested
    help information. Since the implementation of plugin server
    variables the help output is now written much later.
  */
  if (opt_error_log && !opt_help)
  {
    if (!log_error_file_ptr[0])
      fn_format(log_error_file, pidfile_name, mysql_data_home, ".err",
                MY_REPLACE_EXT); /* replace '.<domain>' by '.err', bug#4997 */
    else
      fn_format(log_error_file, log_error_file_ptr, mysql_data_home, ".err",
                MY_UNPACK_FILENAME | MY_SAFE_PATH);
    /*
      _ptr may have been set to my_disabled_option or "" if no argument was
      passed, but we need to show the real name in SHOW VARIABLES:
    */
    log_error_file_ptr= log_error_file;
    if (!log_error_file[0])
      opt_error_log= 0;                         // Too long file name
    else
    {
      my_bool res;
#ifndef EMBEDDED_LIBRARY
      res= reopen_fstreams(log_error_file, stdout, stderr);
#else
      res= reopen_fstreams(log_error_file, NULL, stderr);
#endif
      if (!res)
        setbuf(stderr, NULL);
    }
  }
  else
    log_error_file_ptr= const_cast<char*>("stderr");

  proc_info_hook= set_thd_stage_info;

#ifdef WITH_PERFSCHEMA_STORAGE_ENGINE
  /*
    Parsing the performance schema command line option may have reported
    warnings/information messages.
    Now that the logger is finally available, and redirected
    to the proper file when the --log--error option is used,
    print the buffered messages to the log.
  */
  buffered_logs.print();
  buffered_logs.cleanup();
#endif /* WITH_PERFSCHEMA_STORAGE_ENGINE */

  /*
    Now that the logger is available, redirect character set
    errors directly to the logger
    (instead of the buffered_logs used at the server startup time).
  */
  my_charset_error_reporter= charset_error_reporter;

  if (transaction_cache_init())
  {
    sql_print_error("Out of memory");
    unireg_abort(1);
  }

  /*
    initialize delegates for extension observers, errors have already
    been reported in the function
  */
  if (delegates_init())
    unireg_abort(1);

  /* need to configure logging before initializing storage engines */
  if (opt_log_slave_updates && !opt_bin_log)
  {
    sql_print_warning("You need to use --log-bin to make "
                    "--log-slave-updates work.");
  }
  if (binlog_format_used && !opt_bin_log)
    sql_print_warning("You need to use --log-bin to make "
                      "--binlog-format work.");

  /* Check that we have not let the format to unspecified at this point */
  DBUG_ASSERT((uint)global_system_variables.binlog_format <=
              array_elements(binlog_format_names)-1);

#ifdef HAVE_REPLICATION
  if (opt_log_slave_updates && replicate_same_server_id)
  {
    if (opt_bin_log)
    {
      sql_print_error("using --replicate-same-server-id in conjunction with \
--log-slave-updates is impossible, it would lead to infinite loops in this \
server.");
      unireg_abort(1);
    }
    else
      sql_print_warning("using --replicate-same-server-id in conjunction with \
--log-slave-updates would lead to infinite loops in this server. However this \
will be ignored as the --log-bin option is not defined.");
  }
#endif

  opt_server_id_mask = ~ulong(0);
#ifdef HAVE_REPLICATION
  opt_server_id_mask = (opt_server_id_bits == 32)?
    ~ ulong(0) : (1 << opt_server_id_bits) -1;
  if (server_id != (server_id & opt_server_id_mask))
  {
    sql_print_error("server-id configured is too large to represent with"
                    "server-id-bits configured.");
    unireg_abort(1);
  }
#endif

  if (opt_bin_log)
  {
    /* Reports an error and aborts, if the --log-bin's path
       is a directory.*/
    if (opt_bin_logname &&
        opt_bin_logname[strlen(opt_bin_logname) - 1] == FN_LIBCHAR)
    {
      sql_print_error("Path '%s' is a directory name, please specify \
a file name for --log-bin option", opt_bin_logname);
      unireg_abort(1);
    }

    /* Reports an error and aborts, if the --log-bin-index's path
       is a directory.*/
    if (opt_binlog_index_name &&
        opt_binlog_index_name[strlen(opt_binlog_index_name) - 1]
        == FN_LIBCHAR)
    {
      sql_print_error("Path '%s' is a directory name, please specify \
a file name for --log-bin-index option", opt_binlog_index_name);
      unireg_abort(1);
    }

    char buf[FN_REFLEN];
    const char *ln;
    ln= mysql_bin_log.generate_name(opt_bin_logname, "-bin", buf);
    if (!opt_bin_logname && !opt_binlog_index_name)
    {
      /*
        User didn't give us info to name the binlog index file.
        Picking `hostname`-bin.index like did in 4.x, causes replication to
        fail if the hostname is changed later. So, we would like to instead
        require a name. But as we don't want to break many existing setups, we
        only give warning, not error.
      */
      sql_print_warning("No argument was provided to --log-bin, and "
                        "--log-bin-index was not used; so replication "
                        "may break when this MySQL server acts as a "
                        "master and has his hostname changed!! Please "
                        "use '--log-bin=%s' to avoid this problem.", ln);
    }
    if (ln == buf)
    {
      my_free(opt_bin_logname);
      opt_bin_logname=my_strdup(key_memory_opt_bin_logname,
                                buf, MYF(0));
    }
    if (mysql_bin_log.open_index_file(opt_binlog_index_name, ln, TRUE))
    {
      unireg_abort(1);
    }
  }

  if (opt_bin_log)
  {
    /*
      opt_bin_logname[0] needs to be checked to make sure opt binlog name is
      not an empty string, incase it is an empty string default file
      extension will be passed
     */
    log_bin_basename=
      rpl_make_log_name(key_memory_MYSQL_BIN_LOG_basename,
                        opt_bin_logname, default_logfile_name,
                        (opt_bin_logname && opt_bin_logname[0]) ? "" : "-bin");
    log_bin_index=
      rpl_make_log_name(key_memory_MYSQL_BIN_LOG_index,
                        opt_binlog_index_name, log_bin_basename, ".index");
    if (log_bin_basename == NULL || log_bin_index == NULL)
    {
      sql_print_error("Unable to create replication path names:"
                      " out of memory or path names too long"
                      " (path name exceeds " STRINGIFY_ARG(FN_REFLEN)
                      " or file name exceeds " STRINGIFY_ARG(FN_LEN) ").");
      unireg_abort(1);
    }
  }

#ifndef EMBEDDED_LIBRARY
  DBUG_PRINT("debug",
             ("opt_bin_logname: %s, opt_relay_logname: %s, pidfile_name: %s",
              opt_bin_logname, opt_relay_logname, pidfile_name));
  if (opt_relay_logname)
  {
    /*
      opt_relay_logname[0] needs to be checked to make sure opt relaylog name is
      not an empty string, incase it is an empty string default file
      extension will be passed
     */
    relay_log_basename=
      rpl_make_log_name(key_memory_MYSQL_RELAY_LOG_basename,
                        opt_relay_logname, default_logfile_name,
                        (opt_relay_logname && opt_relay_logname[0]) ? "" : "-relay-bin");
    relay_log_index=
      rpl_make_log_name(key_memory_MYSQL_RELAY_LOG_index,
                        opt_relaylog_index_name, relay_log_basename, ".index");
    if (relay_log_basename == NULL || relay_log_index == NULL)
    {
      sql_print_error("Unable to create replication path names:"
                      " out of memory or path names too long"
                      " (path name exceeds " STRINGIFY_ARG(FN_REFLEN)
                      " or file name exceeds " STRINGIFY_ARG(FN_LEN) ").");
      unireg_abort(1);
    }
  }
#endif /* !EMBEDDED_LIBRARY */

  /* call ha_init_key_cache() on all key caches to init them */
  process_key_caches(&ha_init_key_cache);

  /* Allow storage engine to give real error messages */
  if (ha_init_errors())
    DBUG_RETURN(1);

  if (opt_ignore_builtin_innodb)
    sql_print_warning("ignore-builtin-innodb is ignored "
                      "and will be removed in future releases.");
  if (gtid_server_init())
  {
    sql_print_error("Failed to initialize GTID structures.");
    unireg_abort(1);
  }

  if (plugin_init(&remaining_argc, remaining_argv,
                  (opt_noacl ? PLUGIN_INIT_SKIP_PLUGIN_TABLE : 0) |
                  (opt_help ? PLUGIN_INIT_SKIP_INITIALIZATION : 0)))
  {
    sql_print_error("Failed to initialize plugins.");
    unireg_abort(1);
  }
  plugins_are_initialized= TRUE;  /* Don't separate from init function */

  Session_tracker session_track_system_variables_check;
  LEX_STRING var_list;
  char *tmp_str;
  size_t len= strlen(global_system_variables.track_sysvars_ptr);
  tmp_str= (char *)my_malloc(PSI_NOT_INSTRUMENTED, len*sizeof(char)+2,
                             MYF(MY_WME));
  strcpy(tmp_str,global_system_variables.track_sysvars_ptr);
  var_list.length= len;
  var_list.str= tmp_str;
  if (session_track_system_variables_check.server_boot_verify(system_charset_info,
	                                                      var_list))
  {
    sql_print_error("The variable session_track_system_variables either has "
	            "duplicate values or invalid values.");
    if (tmp_str)
      my_free(tmp_str);
    unireg_abort(1);
  }
  if (tmp_str)
    my_free(tmp_str);
  /* we do want to exit if there are any other unknown options */
  if (remaining_argc > 1)
  {
    int ho_error;
    struct my_option no_opts[]=
    {
      {0, 0, 0, 0, 0, 0, GET_NO_ARG, NO_ARG, 0, 0, 0, 0, 0, 0}
    };
    /*
      We need to eat any 'loose' arguments first before we conclude
      that there are unprocessed options.
    */
    my_getopt_skip_unknown= 0;

    if ((ho_error= handle_options(&remaining_argc, &remaining_argv, no_opts,
                                  mysqld_get_one_option)))
      unireg_abort(ho_error);
    /* Add back the program name handle_options removes */
    remaining_argc++;
    remaining_argv--;
    my_getopt_skip_unknown= TRUE;

    if (remaining_argc > 1)
    {
      my_message_local(ERROR_LEVEL, "Too many arguments (first extra is '%s').",
                       remaining_argv[1]);
      my_message_local(INFORMATION_LEVEL, "Use --verbose --help to get a list "
                       "of available options!");
      unireg_abort(1);
    }
  }

  if (opt_help)
    unireg_abort(0);

  /* if the errmsg.sys is not loaded, terminate to maintain behaviour */
  if (!DEFAULT_ERRMSGS[0][0])
  {
    sql_print_error("Unable to read errmsg.sys file");
    unireg_abort(1);
  }

  /* We have to initialize the storage engines before CSV logging */
  if (ha_init())
  {
    sql_print_error("Can't init databases");
    unireg_abort(1);
  }

  if (opt_bootstrap)
    log_output_options= LOG_FILE;

  /*
    Issue a warning if there were specified additional options to the
    log-output along with NONE. Probably this wasn't what user wanted.
  */
  if ((log_output_options & LOG_NONE) && (log_output_options & ~LOG_NONE))
    sql_print_warning("There were other values specified to "
                      "log-output besides NONE. Disabling slow "
                      "and general logs anyway.");

  if (log_output_options & LOG_TABLE)
  {
    /* Fall back to log files if the csv engine is not loaded. */
    LEX_STRING csv_name={C_STRING_WITH_LEN("csv")};
    if (!plugin_is_ready(&csv_name, MYSQL_STORAGE_ENGINE_PLUGIN))
    {
      sql_print_error("CSV engine is not present, falling back to the "
                      "log files");
      log_output_options= (log_output_options & ~LOG_TABLE) | LOG_FILE;
    }
  }

  query_logger.set_handlers(log_output_options);

  // Open slow log file if enabled.
  if (opt_slow_log && query_logger.reopen_log_file(QUERY_LOG_SLOW))
    opt_slow_log= false;

  // Open general log file if enabled.
  if (opt_general_log && query_logger.reopen_log_file(QUERY_LOG_GENERAL))
    opt_general_log= false;

  /*
    Set the default storage engines
  */
  if (initialize_storage_engine(default_storage_engine, "",
                                &global_system_variables.table_plugin))
    unireg_abort(1);
  if (initialize_storage_engine(default_tmp_storage_engine, " temp",
                                &global_system_variables.temp_table_plugin))
    unireg_abort(1);

  if (total_ha_2pc > 1 || (1 == total_ha_2pc && opt_bin_log))
  {
    if (opt_bin_log)
      tc_log= &mysql_bin_log;
    else
      tc_log= &tc_log_mmap;
  }
  else
    tc_log= &tc_log_dummy;

  if (tc_log->open(opt_bin_log ? opt_bin_logname : opt_tc_log_file))
  {
    sql_print_error("Can't init tc log");
    unireg_abort(1);
  }

  if (ha_recover(0))
  {
    unireg_abort(1);
  }

  if (gtid_mode >= 1 && opt_bootstrap)
  {
    sql_print_warning("Bootstrap mode disables GTIDs. Bootstrap mode "
    "should only be used by mysql_install_db which initializes the MySQL "
    "data directory and creates system tables.");
    gtid_mode= 0;
  }
  if (gtid_mode >= 1 && !(opt_bin_log && opt_log_slave_updates))
  {
    sql_print_error("--gtid-mode=ON or UPGRADE_STEP_1 or UPGRADE_STEP_2 requires --log-bin and --log-slave-updates");
    unireg_abort(1);
  }
  if (gtid_mode >= 2 && !enforce_gtid_consistency)
  {
    sql_print_error("--gtid-mode=ON or UPGRADE_STEP_1 requires --enforce-gtid-consistency");
    unireg_abort(1);
  }
  if (gtid_mode == 1 || gtid_mode == 2)
  {
    sql_print_error("--gtid-mode=UPGRADE_STEP_1 or --gtid-mode=UPGRADE_STEP_2 are not yet supported");
    unireg_abort(1);
  }

  if (opt_bin_log)
  {
    /*
      Configures what object is used by the current log to store processed
      gtid(s). This is necessary in the MYSQL_BIN_LOG::MYSQL_BIN_LOG to
      corretly compute the set of previous gtids.
    */
    mysql_bin_log.set_previous_gtid_set(
      const_cast<Gtid_set*>(gtid_state->get_logged_gtids()));

    mysql_mutex_t *log_lock= mysql_bin_log.get_log_lock();
    mysql_mutex_lock(log_lock);

    if (mysql_bin_log.open_binlog(opt_bin_logname, 0,
                                  max_binlog_size, false,
                                  true/*need_lock_index=true*/,
                                  true/*need_sid_lock=true*/,
                                  NULL))
    {
      mysql_mutex_unlock(log_lock);
      unireg_abort(1);
    }
    mysql_mutex_unlock(log_lock);
  }

#ifdef HAVE_REPLICATION
  if (opt_bin_log && expire_logs_days)
  {
    time_t purge_time= server_start_time - expire_logs_days*24*60*60;
    if (purge_time >= 0)
      mysql_bin_log.purge_logs_before_date(purge_time, true);
  }
#endif

  if (opt_myisam_log)
    (void) mi_log(1);

#if defined(HAVE_MLOCKALL) && defined(MCL_CURRENT) && !defined(EMBEDDED_LIBRARY)
  if (locked_in_memory && !getuid())
  {
    if (setreuid((uid_t)-1, 0) == -1)
    {                        // this should never happen
      sql_print_error("setreuid: %s", strerror(errno));
      unireg_abort(1);
    }
    if (mlockall(MCL_CURRENT))
    {
      sql_print_warning("Failed to lock memory. Errno: %d\n",errno); /* purecov: inspected */
      locked_in_memory= 0;
    }
#ifndef _WIN32
    if (user_info)
      set_user(mysqld_user, user_info);
#endif
  }
  else
#endif
    locked_in_memory=0;

  ft_init_stopwords();

  init_max_user_conn();
  init_update_queries();
  DBUG_RETURN(0);
}


#ifndef EMBEDDED_LIBRARY
#ifdef _WIN32

pthread_handler_t handle_shutdown(void *arg)
{
  MSG msg;
  my_thread_init();
  /* This call should create the message queue for this thread. */
  PeekMessage(&msg, NULL, 1, 65534,PM_NOREMOVE);
  if (WaitForSingleObject(hEventShutdown,INFINITE)==WAIT_OBJECT_0)
  {
    sql_print_information(ER_DEFAULT(ER_NORMAL_SHUTDOWN), my_progname);
    abort_loop= 1;
    close_connections();
    my_thread_end();
    pthread_exit(0);
  }
  return 0;
}


static void create_shutdown_thread()
{
  hEventShutdown=CreateEvent(0, FALSE, FALSE, shutdown_event_name);
  pthread_attr_t thr_attr;
  DBUG_ENTER("create_shutdown_thread");
  pthread_t shutdown_thread;

  pthread_attr_init(&thr_attr);
  pthread_attr_setscope(&thr_attr, PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setdetachstate(&thr_attr, PTHREAD_CREATE_JOINABLE);

  if (pthread_create_get_handle(&shutdown_thread, &thr_attr,
                                handle_shutdown, 0, &shutdown_thr_handle))
    sql_print_warning("Can't create thread to handle shutdown requests"
                      " (errno= %d)", errno);
  pthread_attr_destroy(&thr_attr);
  // On "Stop Service" we have to do regular shutdown
  Service.SetShutdownEvent(hEventShutdown);
}
#endif /* _WIN32 */

#ifndef DBUG_OFF
/*
  Debugging helper function to keep the locale database
  (see sql_locale.cc) and max_month_name_length and
  max_day_name_length variable values in consistent state.
*/
static void test_lc_time_sz()
{
  DBUG_ENTER("test_lc_time_sz");
  for (MY_LOCALE **loc= my_locales; *loc; loc++)
  {
    uint max_month_len= 0;
    uint max_day_len = 0;
    for (const char **month= (*loc)->month_names->type_names; *month; month++)
    {
      set_if_bigger(max_month_len,
                    my_numchars_mb(&my_charset_utf8_general_ci,
                                   *month, *month + strlen(*month)));
    }
    for (const char **day= (*loc)->day_names->type_names; *day; day++)
    {
      set_if_bigger(max_day_len,
                    my_numchars_mb(&my_charset_utf8_general_ci,
                                   *day, *day + strlen(*day)));
    }
    if ((*loc)->max_month_name_length != max_month_len ||
        (*loc)->max_day_name_length != max_day_len)
    {
      DBUG_PRINT("Wrong max day name(or month name) length for locale:",
                 ("%s", (*loc)->name));
      DBUG_ASSERT(0);
    }
  }
  DBUG_VOID_RETURN;
}
#endif//DBUG_OFF

#ifdef _WIN32
int win_main(int argc, char **argv)
#else
int mysqld_main(int argc, char **argv)
#endif
{
  /*
    Perform basic thread library and malloc initialization,
    to be able to read defaults files and parse options.
  */
  my_progname= argv[0];

#ifndef _WIN32
#ifdef WITH_PERFSCHEMA_STORAGE_ENGINE
  pre_initialize_performance_schema();
#endif /*WITH_PERFSCHEMA_STORAGE_ENGINE */

  // For windows, my_init() is called from the win specific mysqld_main
  if (my_init())                 // init my_sys library & pthreads
  {
    my_message_local(ERROR_LEVEL, "my_init() failed.");
    return 1;
  }
#endif /* _WIN32 */

  orig_argc= argc;
  orig_argv= argv;
  my_getopt_use_args_separator= TRUE;
  if (load_defaults(MYSQL_CONFIG_NAME, load_default_groups, &argc, &argv))
    return 1;
  my_getopt_use_args_separator= FALSE;
  defaults_argc= argc;
  defaults_argv= argv;
  remaining_argc= argc;
  remaining_argv= argv;

  /* Must be initialized early for comparison of options name */
  system_charset_info= &my_charset_utf8_general_ci;

  init_sql_statement_names();
  sys_var_init();

  int ho_error;

#ifdef WITH_PERFSCHEMA_STORAGE_ENGINE
  /*
    Initialize the array of performance schema instrument configurations.
  */
  init_pfs_instrument_array();
#endif /* WITH_PERFSCHEMA_STORAGE_ENGINE */

  ho_error= handle_early_options();

  ulong requested_open_files;
  adjust_related_options(&requested_open_files);

#ifdef WITH_PERFSCHEMA_STORAGE_ENGINE
  if (pfs_param.m_enabled)
    load_perfschema_engine= true;

  if (ho_error == 0)
  {
    if (pfs_param.m_enabled && !opt_help && !opt_bootstrap)
    {
      /* Add sizing hints from the server sizing parameters. */
      pfs_param.m_hints.m_table_definition_cache= table_def_size;
      pfs_param.m_hints.m_table_open_cache= table_cache_size;
      pfs_param.m_hints.m_max_connections= max_connections;
      pfs_param.m_hints.m_open_files_limit= requested_open_files;
      pfs_param.m_hints.m_max_prepared_stmt_count= max_prepared_stmt_count;
      PSI_hook= initialize_performance_schema(&pfs_param);
      if (PSI_hook == NULL)
      {
        pfs_param.m_enabled= false;
        buffered_logs.buffer(WARNING_LEVEL,
                             "Performance schema disabled (reason: init failed).");
      }
    }
  }
#else
  /*
    Other provider of the instrumentation interface should
    initialize PSI_hook here:
    - HAVE_PSI_INTERFACE is for the instrumentation interface
    - WITH_PERFSCHEMA_STORAGE_ENGINE is for one implementation
      of the interface,
    but there could be alternate implementations, which is why
    these two defines are kept separate.
  */
#endif /* WITH_PERFSCHEMA_STORAGE_ENGINE */

#ifdef HAVE_PSI_INTERFACE
  /*
    Obtain the current performance schema instrumentation interface,
    if available.
  */
  if (PSI_hook)
  {
    PSI *psi_server= (PSI*) PSI_hook->get_interface(PSI_CURRENT_VERSION);
    if (likely(psi_server != NULL))
    {
      set_psi_server(psi_server);

      /*
        Now that we have parsed the command line arguments, and have initialized
        the performance schema itself, the next step is to register all the
        server instruments.
      */
      init_server_psi_keys();
      /* Instrument the main thread */
      PSI_thread *psi= PSI_THREAD_CALL(new_thread)(key_thread_main, NULL, 0);
      PSI_THREAD_CALL(set_thread)(psi);

      /*
        Now that some instrumentation is in place,
        recreate objects which were initialised early,
        so that they are instrumented as well.
      */
      my_thread_global_reinit();
    }
  }
#endif /* HAVE_PSI_INTERFACE */

  init_error_log_mutex();
  local_message_hook= error_log_print;  // we never change this in embedded

  /* Initialize audit interface globals. Audit plugins are inited later. */
  mysql_audit_initialize();

  /*
    Perform basic query log initialization. Should be called after
    MY_INIT, as it initializes mutexes.
  */
  query_logger.init();

  if (ho_error)
  {
    /*
      Parsing command line option failed,
      Since we don't have a workable remaining_argc/remaining_argv
      to continue the server initialization, this is as far as this
      code can go.
      This is the best effort to log meaningful messages:
      - messages will be printed to stderr, which is not redirected yet,
      - messages will be printed in the NT event log, for windows.
    */
    buffered_logs.print();
    buffered_logs.cleanup();
    /*
      Not enough initializations for unireg_abort()
      Using exit() for windows.
    */
    exit (ho_error);
  }

  if (init_common_variables())
    unireg_abort(1);        // Will do exit

  my_init_signals();

  size_t guardize= 0;
  int retval= pthread_attr_getguardsize(&connection_attrib, &guardize);
  DBUG_ASSERT(retval == 0);
  if (retval != 0)
    guardize= my_thread_stack_size;

#if defined(__ia64__) || defined(__ia64)
  /*
    Peculiar things with ia64 platforms - it seems we only have half the
    stack size in reality, so we have to double it here
  */
  guardize= my_thread_stack_size;
#endif

  pthread_attr_setstacksize(&connection_attrib,
                            my_thread_stack_size + guardize);

  {
    /* Retrieve used stack size;  Needed for checking stack overflows */
    size_t stack_size= 0;
    pthread_attr_getstacksize(&connection_attrib, &stack_size);

    /* We must check if stack_size = 0 as Solaris 2.9 can return 0 here */
    if (stack_size && stack_size < (my_thread_stack_size + guardize))
    {
      sql_print_warning("Asked for %lu thread stack, but got %ld",
                        my_thread_stack_size + guardize, (long) stack_size);
#if defined(__ia64__) || defined(__ia64)
      my_thread_stack_size= stack_size / 2;
#else
      my_thread_stack_size= stack_size - guardize;
#endif
    }
  }

#ifndef DBUG_OFF
  test_lc_time_sz();
  srand(time(NULL));
#endif

  /*
    We have enough space for fiddling with the argv, continue
  */
  if (my_setwd(mysql_real_data_home,MYF(MY_WME)) && !opt_help)
    unireg_abort(1);        /* purecov: inspected */

#ifndef _WIN32
  if ((user_info= check_user(mysqld_user)))
  {
#if defined(HAVE_MLOCKALL) && defined(MCL_CURRENT)
    if (locked_in_memory) // getuid() == 0 here
      set_effective_user(user_info);
    else
#endif
      set_user(mysqld_user, user_info);
  }
#endif // !_WIN32

  //If the binlog is enabled, one needs to provide a server-id
  if (opt_bin_log && !(server_id_supplied) )
  {
    sql_print_error("You have enabled the binary log, but you haven't provided "
                    "the mandatory server-id. Please refer to the proper "
                    "server start-up parameters documentation");
    unireg_abort(1);
  }

  /* 
   The subsequent calls may take a long time : e.g. innodb log read.
   Thus set the long running service control manager timeout
  */
#if defined(_WIN32)
  Service.SetSlowStarting(slow_start_timeout);
#endif

  if (init_server_components())
    unireg_abort(1);

  /*
    Each server should have one UUID. We will create it automatically, if it
    does not exist.
   */
  if (!opt_bootstrap)
  {
    if (init_server_auto_options())
    {
      sql_print_error("Initialzation of the server's UUID failed because it could"
                      " not be read from the auto.cnf file. If this is a new"
                      " server, the initialization failed because it was not"
                      " possible to generate a new UUID.");
      unireg_abort(1);
    }

    if (opt_bin_log)
    {
      /*
        Add server_uuid to the sid_map.  This must be done after
        server_uuid has been initialized in init_server_auto_options and
        after the binary log (and sid_map file) has been initialized in
        init_server_components().

        No error message is needed: init_sid_map() prints a message.
      */
      global_sid_lock->rdlock();
      int ret= gtid_state->init();
      global_sid_lock->unlock();
      if (ret)
        unireg_abort(1);

      if (mysql_bin_log.init_gtid_sets(
            const_cast<Gtid_set *>(gtid_state->get_logged_gtids()),
            const_cast<Gtid_set *>(gtid_state->get_lost_gtids()),
            NULL,
            opt_master_verify_checksum,
            true/*true=need lock*/))
        unireg_abort(1);

      /*
        Write the previous set of gtids at this point because during
        the creation of the binary log this is not done as we cannot
        move the init_gtid_sets() to a place before openning the binary
        log. This requires some investigation.

        /Alfranio
      */
      if (gtid_mode > 0)
      {
        global_sid_lock->wrlock();
        const Gtid_set *logged_gtids= gtid_state->get_logged_gtids();
        if (gtid_mode > 1 || !logged_gtids->is_empty())
        {
          Previous_gtids_log_event prev_gtids_ev(logged_gtids);
          global_sid_lock->unlock();

          prev_gtids_ev.checksum_alg= binlog_checksum_options;

          if (prev_gtids_ev.write(mysql_bin_log.get_log_file()))
            unireg_abort(1);
          mysql_bin_log.add_bytes_written(prev_gtids_ev.data_written);

          if (flush_io_cache(mysql_bin_log.get_log_file()) ||
              mysql_file_sync(mysql_bin_log.get_log_file()->file, MYF(MY_WME)))
            unireg_abort(1);
        }
        else
          global_sid_lock->unlock();
      }
    }
  }

  if (init_ssl())
    unireg_abort(1);
  network_init();

#ifdef _WIN32
  if (!opt_console)
  {
    if (reopen_fstreams(log_error_file, stdout, stderr))
      unireg_abort(1);
    setbuf(stderr, NULL);
    FreeConsole();        // Remove window
  }
#endif

  /*
   Initialize my_str_malloc(), my_str_realloc() and my_str_free()
  */
  my_str_malloc= &my_str_malloc_mysqld;
  my_str_free= &my_str_free_mysqld;
  my_str_realloc= &my_str_realloc_mysqld;

  /*
    init signals & alarm
    After this we can't quit by a simple unireg_abort
  */
  error_handler_hook= my_message_sql;

#ifndef _WIN32
  start_signal_handler();
#endif

  /* Save pid of this process in a file */
  if (!opt_bootstrap)
    create_pid_file();

  if (mysql_rm_tmp_tables() || acl_init(opt_noacl) ||
      my_tz_init((THD *)0, default_tz_name, opt_bootstrap))
  {
    abort_loop=1;

    (void) pthread_kill(signal_thread_id, MYSQL_KILL_SIGNAL);

    delete_pid_file(MYF(MY_WME));

    if (mysqld_socket_acceptor != NULL)
    {
      delete mysqld_socket_acceptor;
      mysqld_socket_acceptor= NULL;
    }
    exit(1);
  }

  if (!opt_noacl)
    (void) grant_init();

  if (!opt_bootstrap)
    servers_init(0);

  if (!opt_noacl)
  {
#ifdef HAVE_DLOPEN
    udf_init();
#endif
  }

  init_status_vars();
  /* If running with bootstrap, do not start replication. */
  if (opt_bootstrap)
    opt_skip_slave_start= 1;

  check_binlog_cache_size(NULL);
  check_binlog_stmt_cache_size(NULL);

  binlog_unsafe_map_init();

  /* If running with bootstrap, do not start replication. */
  if (!opt_bootstrap)
  {
    // Make @@slave_skip_errors show the nice human-readable value.
    set_slave_skip_errors(&opt_slave_skip_errors);

    /*
      init_slave() must be called after the thread keys are created.
    */
    if (server_id != 0)
      init_slave(); /* Ignoring errors while configuring replication. */
  }

#ifdef WITH_PERFSCHEMA_STORAGE_ENGINE
  initialize_performance_schema_acl(opt_bootstrap);
  /*
    Do not check the structure of the performance schema tables
    during bootstrap:
    - the tables are not supposed to exist yet, bootstrap will create them
    - a check would print spurious error messages
  */
  if (! opt_bootstrap && load_perfschema_engine)
    check_performance_schema();
#endif

  initialize_information_schema_acl();

  execute_ddl_log_recovery();

  if (Events::init(opt_noacl || opt_bootstrap))
    unireg_abort(1);

  if (opt_bootstrap)
  {
    /* Signal threads waiting for server to be started */
    mysql_mutex_lock(&LOCK_server_started);
    mysqld_server_started= true;
    mysql_cond_broadcast(&COND_server_started);
    mysql_mutex_unlock(&LOCK_server_started);

    int error= bootstrap(mysql_stdin);
    unireg_abort(error ? 1 : 0);
  }
  if (opt_init_file && *opt_init_file)
  {
    if (read_init_file(opt_init_file))
      unireg_abort(1);
  }

#ifdef _WIN32
  create_shutdown_thread();
#endif
  start_handle_manager();

  sql_print_information(ER_DEFAULT(ER_STARTUP),
                        my_progname,
                        server_version,
#ifdef HAVE_SYS_UN_H
                        (opt_bootstrap ? (char*) "" : mysqld_unix_port),
#else
                        (char*) "",
#endif
                         mysqld_port,
                         MYSQL_COMPILATION_COMMENT);
#if defined(_WIN32)
  Service.SetRunning();
#endif


  /* Signal threads waiting for server to be started */
  mysql_mutex_lock(&LOCK_server_started);
  mysqld_server_started= true;
  mysql_cond_broadcast(&COND_server_started);
  mysql_mutex_unlock(&LOCK_server_started);

#ifdef WITH_NDBCLUSTER_STORAGE_ENGINE
  /* engine specific hook, to be made generic */
  if (ndb_wait_setup_func && ndb_wait_setup_func(opt_ndb_wait_setup))
  {
    sql_print_warning("NDB : Tables not available after %lu seconds."
                      "  Consider increasing --ndb-wait-setup value",
                      opt_ndb_wait_setup);
  }
#endif

  DBUG_PRINT("info", ("Block, listening for incoming connections"));

#if defined(_WIN32)
  setup_conn_event_handler_threads();
#else
  mysql_mutex_lock(&LOCK_socket_listener_active);
  // Make it possible for close_connections() to kill the listener.
  socket_listener_active= true;
  mysql_mutex_unlock(&LOCK_socket_listener_active);
  (void) mysqld_socket_acceptor->connection_event_loop();
#endif /* _WIN32 */

  DBUG_PRINT("info", ("No longer listening for incoming connections"));

#ifndef _WIN32
  mysql_mutex_lock(&LOCK_socket_listener_active);
  // Notify close_connections() that we have stopped listening for connections.
  socket_listener_active= false;
  mysql_cond_broadcast(&COND_socket_listener_active);
  mysql_mutex_unlock(&LOCK_socket_listener_active);
#endif // !_WIN32

#ifdef HAVE_PSI_THREAD_INTERFACE
  /*
    Disable the main thread instrumentation,
    to avoid recording events during the shutdown.
  */
  PSI_THREAD_CALL(delete_current_thread)();
#endif

  DBUG_PRINT("info", ("Waiting for shutdown proceed"));
  int ret= 0;
#ifdef _WIN32
  if (shutdown_thr_handle)
    ret= pthread_join_with_handle(shutdown_thr_handle);
  shutdown_thr_handle= NULL;
  if (0 != ret)
    sql_print_warning("Could not join shutdown thread. error:%d", ret);
#else
  if (signal_thread_id != 0)
    ret= pthread_join(signal_thread_id, NULL);
  signal_thread_id= 0;
  if (0 != ret)
    sql_print_warning("Could not join signal_thread. error:%d", ret);
#endif

  clean_up(1);
  mysqld_exit(0);
}


/****************************************************************************
  Main and thread entry function for Win32
  (all this is needed only to run mysqld as a service on WinNT)
****************************************************************************/

#if defined(_WIN32)
int mysql_service(void *p)
{
  if (my_thread_init())
    return 1;

  if (use_opt_args)
    win_main(opt_argc, opt_argv);
  else
    win_main(Service.my_argc, Service.my_argv);

  my_thread_end();
  return 0;
}


/* Quote string if it contains space, else copy */

static char *add_quoted_string(char *to, const char *from, char *to_end)
{
  uint length= (uint) (to_end-to);

  if (!strchr(from, ' '))
    return strmake(to, from, length-1);
  return strxnmov(to, length-1, "\"", from, "\"", NullS);
}


/**
  Handle basic handling of services, like installation and removal.

  @param argv             Pointer to argument list
  @param servicename    Internal name of service
  @param displayname    Display name of service (in taskbar ?)
  @param file_path    Path to this program
  @param startup_option Startup option to mysqld

  @retval
    0   option handled
  @retval
    1   Could not handle option
*/

static bool
default_service_handling(char **argv,
       const char *servicename,
       const char *displayname,
       const char *file_path,
       const char *extra_opt,
       const char *account_name)
{
  char path_and_service[FN_REFLEN+FN_REFLEN+32], *pos, *end;
  const char *opt_delim;
  end= path_and_service + sizeof(path_and_service)-3;

  /* We have to quote filename if it contains spaces */
  pos= add_quoted_string(path_and_service, file_path, end);
  if (extra_opt && *extra_opt)
  {
    /*
     Add option after file_path. There will be zero or one extra option.  It's
     assumed to be --defaults-file=file but isn't checked.  The variable (not
     the option name) should be quoted if it contains a string.
    */
    *pos++= ' ';
    if (opt_delim= strchr(extra_opt, '='))
    {
      size_t length= ++opt_delim - extra_opt;
      pos= my_stpnmov(pos, extra_opt, length);
    }
    else
      opt_delim= extra_opt;

    pos= add_quoted_string(pos, opt_delim, end);
  }
  /* We must have servicename last */
  *pos++= ' ';
  (void) add_quoted_string(pos, servicename, end);

  if (Service.got_service_option(argv, "install"))
  {
    Service.Install(1, servicename, displayname, path_and_service,
                    account_name);
    return 0;
  }
  if (Service.got_service_option(argv, "install-manual"))
  {
    Service.Install(0, servicename, displayname, path_and_service,
                    account_name);
    return 0;
  }
  if (Service.got_service_option(argv, "remove"))
  {
    Service.Remove(servicename);
    return 0;
  }
  return 1;
}


int mysqld_main(int argc, char **argv)
{
  /*
    When several instances are running on the same machine, we
    need to have an  unique  named  hEventShudown  through the
    application PID e.g.: MySQLShutdown1890; MySQLShutdown2342
  */
  int10_to_str((int) GetCurrentProcessId(),my_stpcpy(shutdown_event_name,
                                                  "MySQLShutdown"), 10);

  /* Must be initialized early for comparison of service name */
  system_charset_info= &my_charset_utf8_general_ci;

#ifdef WITH_PERFSCHEMA_STORAGE_ENGINE
  pre_initialize_performance_schema();
#endif /*WITH_PERFSCHEMA_STORAGE_ENGINE */

  if (my_init())
  {
    my_message_local(ERROR_LEVEL, "my_init() failed.");
    return 1;
  }

  if (Service.GetOS())  /* true NT family */
  {
    char file_path[FN_REFLEN];
    my_path(file_path, argv[0], "");          /* Find name in path */
    fn_format(file_path,argv[0],file_path,"",
        MY_REPLACE_DIR | MY_UNPACK_FILENAME | MY_RESOLVE_SYMLINKS);

    if (argc == 2)
    {
      if (!default_service_handling(argv, MYSQL_SERVICENAME, MYSQL_SERVICENAME,
           file_path, "", NULL))
  return 0;
      if (Service.IsService(argv[1]))        /* Start an optional service */
      {
  /*
    Only add the service name to the groups read from the config file
    if it's not "MySQL". (The default service name should be 'mysqld'
    but we started a bad tradition by calling it MySQL from the start
    and we are now stuck with it.
  */
  if (my_strcasecmp(system_charset_info, argv[1],"mysql"))
    load_default_groups[load_default_groups_sz-2]= argv[1];
        start_mode= 1;
        Service.Init(argv[1], mysql_service);
        return 0;
      }
    }
    else if (argc == 3) /* install or remove any optional service */
    {
      if (!default_service_handling(argv, argv[2], argv[2], file_path, "",
                                    NULL))
  return 0;
      if (Service.IsService(argv[2]))
      {
  /*
    mysqld was started as
    mysqld --defaults-file=my_path\my.ini service-name
  */
  use_opt_args=1;
  opt_argc= 2;        // Skip service-name
  opt_argv=argv;
  start_mode= 1;
  if (my_strcasecmp(system_charset_info, argv[2],"mysql"))
    load_default_groups[load_default_groups_sz-2]= argv[2];
  Service.Init(argv[2], mysql_service);
  return 0;
      }
    }
    else if (argc == 4 || argc == 5)
    {
      /*
        This may seem strange, because we handle --local-service while
        preserving 4.1's behavior of allowing any one other argument that is
        passed to the service on startup. (The assumption is that this is
        --defaults-file=file, but that was not enforced in 4.1, so we don't
        enforce it here.)
      */
      const char *extra_opt= NullS;
      const char *account_name = NullS;
      int index;
      for (index = 3; index < argc; index++)
      {
        if (!strcmp(argv[index], "--local-service"))
          account_name= "NT AUTHORITY\\LocalService";
        else
          extra_opt= argv[index];
      }

      if (argc == 4 || account_name)
        if (!default_service_handling(argv, argv[2], argv[2], file_path,
                                      extra_opt, account_name))
          return 0;
    }
    else if (argc == 1 && Service.IsService(MYSQL_SERVICENAME))
    {
      /* start the default service */
      start_mode= 1;
      Service.Init(MYSQL_SERVICENAME, mysql_service);
      return 0;
    }
  }
  /* Start as standalone server */
  Service.my_argc=argc;
  Service.my_argv=argv;
  mysql_service(NULL);
  return 0;
}
#endif // _WIN32
#endif // !EMBEDDED_LIBRARY


static bool read_init_file(char *file_name)
{
  MYSQL_FILE *file;
  DBUG_ENTER("read_init_file");
  DBUG_PRINT("enter",("name: %s",file_name));

  sql_print_information("Execution of init_file \'%s\' started.", file_name);

  if (!(file= mysql_file_fopen(key_file_init, file_name,
                               O_RDONLY, MYF(MY_WME))))
    DBUG_RETURN(TRUE);
  (void) bootstrap(file);
  mysql_file_fclose(file, MYF(MY_WME));

  sql_print_information("Execution of init_file \'%s\' ended.", file_name);

  DBUG_RETURN(FALSE);
}


/****************************************************************************
  Handle start options
******************************************************************************/

/**
  Process command line options flagged as 'early'.
  Some components needs to be initialized as early as possible,
  because the rest of the server initialization depends on them.
  Options that needs to be parsed early includes:
  - the performance schema, when compiled in,
  - options related to the help,
  - options related to the bootstrap
  The performance schema needs to be initialized as early as possible,
  before to-be-instrumented objects of the server are initialized.
*/
int handle_early_options()
{
  int ho_error;
  vector<my_option> all_early_options;
  all_early_options.reserve(100);

  my_getopt_register_get_addr(NULL);
  /* Skip unknown options so that they may be processed later */
  my_getopt_skip_unknown= TRUE;

  /* Add the system variables parsed early */
  sys_var_add_options(&all_early_options, sys_var::PARSE_EARLY);

  /* Add the command line options parsed early */
  for (my_option *opt= my_long_early_options;
       opt->name != NULL;
       opt++)
    all_early_options.push_back(*opt);

  add_terminator(&all_early_options);

  /*
    Logs generated while parsing the command line
    options are buffered and printed later.
  */
  buffered_logs.init();
  my_getopt_error_reporter= buffered_option_error_reporter;
  my_charset_error_reporter= buffered_option_error_reporter;

  ho_error= handle_options(&remaining_argc, &remaining_argv,
                           &all_early_options[0], mysqld_get_one_option);
  if (ho_error == 0)
  {
    /* Add back the program name handle_options removes */
    remaining_argc++;
    remaining_argv--;
  }

  // Swap with an empty vector, i.e. delete elements and free allocated space.
  vector<my_option>().swap(all_early_options);

  return ho_error;
}

/**
  Adjust @c open_files_limit.
  Computation is  based on:
  - @c max_connections,
  - @c table_cache_size,
  - the platform max open file limit.
*/
void adjust_open_files_limit(ulong *requested_open_files)
{
  ulong limit_1;
  ulong limit_2;
  ulong limit_3;
  ulong request_open_files;
  ulong effective_open_files;

  /* MyISAM requires two file handles per table. */
  limit_1= 10 + max_connections + table_cache_size * 2;

  /*
    We are trying to allocate no less than max_connections*5 file
    handles (i.e. we are trying to set the limit so that they will
    be available).
  */
  limit_2= max_connections * 5;

  /* Try to allocate no less than 5000 by default. */
  limit_3= open_files_limit ? open_files_limit : 5000;

  request_open_files= max<ulong>(max<ulong>(limit_1, limit_2), limit_3);

  /* Notice: my_set_max_open_files() may return more than requested. */
  effective_open_files= my_set_max_open_files(request_open_files);

  if (effective_open_files < request_open_files)
  {
    char msg[1024];

    if (open_files_limit == 0)
    {
      snprintf(msg, sizeof(msg),
               "Changed limits: max_open_files: %lu (requested %lu)",
               effective_open_files, request_open_files);
      buffered_logs.buffer(WARNING_LEVEL, msg);
    }
    else
    {
      snprintf(msg, sizeof(msg),
               "Could not increase number of max_open_files to "
               "more than %lu (request: %lu)",
               effective_open_files, request_open_files);
      buffered_logs.buffer(WARNING_LEVEL, msg);
    }
  }

  open_files_limit= effective_open_files;
  if (requested_open_files)
    *requested_open_files= min<ulong>(effective_open_files, request_open_files);
}

void adjust_max_connections(ulong requested_open_files)
{
  ulong limit;

  limit= requested_open_files - 10 - TABLE_OPEN_CACHE_MIN * 2;

  if (limit < max_connections)
  {
    char msg[1024];

    snprintf(msg, sizeof(msg),
             "Changed limits: max_connections: %lu (requested %lu)",
             limit, max_connections);
    buffered_logs.buffer(WARNING_LEVEL, msg);

    // This can be done unprotected since it is only called on startup.
    max_connections= limit;
  }
}

void adjust_table_cache_size(ulong requested_open_files)
{
  ulong limit;

  limit= max<ulong>((requested_open_files - 10 - max_connections) / 2,
                    TABLE_OPEN_CACHE_MIN);

  if (limit < table_cache_size)
  {
    char msg[1024];

    snprintf(msg, sizeof(msg),
             "Changed limits: table_cache: %lu (requested %lu)",
             limit, table_cache_size);
    buffered_logs.buffer(WARNING_LEVEL, msg);

    table_cache_size= limit;
  }

  table_cache_size_per_instance= table_cache_size / table_cache_instances;
}

void adjust_table_def_size()
{
  longlong default_value;
  sys_var *var;

  default_value= min<longlong> (400 + table_cache_size / 2, 2000);
  var= intern_find_sys_var(STRING_WITH_LEN("table_definition_cache"));
  DBUG_ASSERT(var != NULL);
  var->update_default(default_value);

  if (! table_definition_cache_specified)
    table_def_size= default_value;
}

void adjust_related_options(ulong *requested_open_files)
{
  /* In bootstrap, disable grant tables (we are about to create them) */
  if (opt_bootstrap)
    opt_noacl= 1;

  /* The order is critical here, because of dependencies. */
  adjust_open_files_limit(requested_open_files);
  adjust_max_connections(*requested_open_files);
  adjust_table_cache_size(*requested_open_files);
  adjust_table_def_size();
}

vector<my_option> all_options;

struct my_option my_long_early_options[]=
{
  {"bootstrap", OPT_BOOTSTRAP, "Used by mysql installation scripts.", 0, 0, 0,
   GET_NO_ARG, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"skip-grant-tables", 0,
   "Start without grant tables. This gives all users FULL ACCESS to all tables.",
   &opt_noacl, &opt_noacl, 0, GET_BOOL, NO_ARG, 0, 0, 0, 0, 0,
   0},
  {"help", '?', "Display this help and exit.",
   &opt_help, &opt_help, 0, GET_BOOL, NO_ARG, 0, 0, 0, 0,
   0, 0},
  {"verbose", 'v', "Used with --help option for detailed help.",
   &opt_verbose, &opt_verbose, 0, GET_BOOL, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"version", 'V', "Output version information and exit.", 0, 0, 0, GET_NO_ARG,
   NO_ARG, 0, 0, 0, 0, 0, 0},
  {0, 0, 0, 0, 0, 0, GET_NO_ARG, NO_ARG, 0, 0, 0, 0, 0, 0}
};

/**
  System variables are automatically command-line options (few
  exceptions are documented in sys_var.h), so don't need
  to be listed here.
*/

struct my_option my_long_options[]=
{
#ifdef HAVE_REPLICATION
  {"abort-slave-event-count", 0,
   "Option used by mysql-test for debugging and testing of replication.",
   &abort_slave_event_count,  &abort_slave_event_count,
   0, GET_INT, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
#endif /* HAVE_REPLICATION */
  {"allow-suspicious-udfs", 0,
   "Allows use of UDFs consisting of only one symbol xxx() "
   "without corresponding xxx_init() or xxx_deinit(). That also means "
   "that one can load any function from any library, for example exit() "
   "from libc.so",
   &opt_allow_suspicious_udfs, &opt_allow_suspicious_udfs,
   0, GET_BOOL, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"ansi", 'a', "Use ANSI SQL syntax instead of MySQL syntax. This mode "
   "will also set transaction isolation level 'serializable'.", 0, 0, 0,
   GET_NO_ARG, NO_ARG, 0, 0, 0, 0, 0, 0},
  /*
    Because Sys_var_bit does not support command-line options, we need to
    explicitely add one for --autocommit
  */
  {"autocommit", 0, "Set default value for autocommit (0 or 1)",
   &opt_autocommit, &opt_autocommit, 0,
   GET_BOOL, OPT_ARG, 1, 0, 0, 0, 0, NULL},
  {"binlog-do-db", OPT_BINLOG_DO_DB,
   "Tells the master it should log updates for the specified database, "
   "and exclude all others not explicitly mentioned.",
   0, 0, 0, GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"binlog-ignore-db", OPT_BINLOG_IGNORE_DB,
   "Tells the master that updates to the given database should not be logged to the binary log.",
   0, 0, 0, GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"binlog-row-event-max-size", 0,
   "The maximum size of a row-based binary log event in bytes. Rows will be "
   "grouped into events smaller than this size if possible. "
   "The value has to be a multiple of 256.",
   &opt_binlog_rows_event_max_size, &opt_binlog_rows_event_max_size,
   0, GET_ULONG, REQUIRED_ARG,
   /* def_value */ 8192, /* min_value */  256, /* max_value */ ULONG_MAX,
   /* sub_size */     0, /* block_size */ 256,
   /* app_type */ 0
  },
  {"character-set-client-handshake", 0,
   "Don't ignore client side character set value sent during handshake.",
   &opt_character_set_client_handshake,
   &opt_character_set_client_handshake,
    0, GET_BOOL, NO_ARG, 1, 0, 0, 0, 0, 0},
  {"character-set-filesystem", 0,
   "Set the filesystem character set.",
   &character_set_filesystem_name,
   &character_set_filesystem_name,
   0, GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0 },
  {"character-set-server", 'C', "Set the default character set.",
   &default_character_set_name, &default_character_set_name,
   0, GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0 },
  {"chroot", 'r', "Chroot mysqld daemon during startup.",
   &mysqld_chroot, &mysqld_chroot, 0, GET_STR, REQUIRED_ARG,
   0, 0, 0, 0, 0, 0},
  {"collation-server", 0, "Set the default collation.",
   &default_collation_name, &default_collation_name,
   0, GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0 },
  {"console", OPT_CONSOLE, "Write error output on screen; don't remove the console window on windows.",
   &opt_console, &opt_console, 0, GET_BOOL, NO_ARG, 0, 0, 0,
   0, 0, 0},
  {"core-file", OPT_WANT_CORE, "Write core on errors.", 0, 0, 0, GET_NO_ARG,
   NO_ARG, 0, 0, 0, 0, 0, 0},
  /* default-storage-engine should have "MyISAM" as def_value. Instead
     of initializing it here it is done in init_common_variables() due
     to a compiler bug in Sun Studio compiler. */
  {"default-storage-engine", 0, "The default storage engine for new tables",
   &default_storage_engine, 0, 0, GET_STR, REQUIRED_ARG,
   0, 0, 0, 0, 0, 0 },
  {"default-tmp-storage-engine", 0, 
    "The default storage engine for new explict temporary tables",
   &default_tmp_storage_engine, 0, 0, GET_STR, REQUIRED_ARG,
   0, 0, 0, 0, 0, 0 },
  {"default-time-zone", 0, "Set the default time zone.",
   &default_tz_name, &default_tz_name,
   0, GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0 },
#ifdef HAVE_OPENSSL
  {"des-key-file", 0,
   "Load keys for des_encrypt() and des_encrypt from given file.",
   &des_key_file, &des_key_file, 0, GET_STR, REQUIRED_ARG,
   0, 0, 0, 0, 0, 0},
#endif /* HAVE_OPENSSL */
#ifdef HAVE_REPLICATION
  {"disconnect-slave-event-count", 0,
   "Option used by mysql-test for debugging and testing of replication.",
   &disconnect_slave_event_count, &disconnect_slave_event_count,
   0, GET_INT, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
#endif /* HAVE_REPLICATION */
  {"exit-info", 'T', "Used for debugging. Use at your own risk.", 0, 0, 0,
   GET_LONG, OPT_ARG, 0, 0, 0, 0, 0, 0},

  {"external-locking", 0, "Use system (external) locking (disabled by "
   "default).  With this option enabled you can run myisamchk to test "
   "(not repair) tables while the MySQL server is running. Disable with "
   "--skip-external-locking.", &opt_external_locking, &opt_external_locking,
   0, GET_BOOL, NO_ARG, 0, 0, 0, 0, 0, 0},
  /* We must always support the next option to make scripts like mysqltest
     easier to do */
  {"gdb", 0,
   "Set up signals usable for debugging.",
   &opt_debugging, &opt_debugging,
   0, GET_BOOL, NO_ARG, 0, 0, 0, 0, 0, 0},
#if defined(HAVE_LINUX_LARGE_PAGES) || defined (HAVE_SOLARIS_LARGE_PAGES)
  {"super-large-pages", 0, "Enable support for super large pages.",
   &opt_super_large_pages, &opt_super_large_pages, 0,
   GET_BOOL, OPT_ARG, 0, 0, 1, 0, 1, 0},
#endif
  {"ignore-db-dir", OPT_IGNORE_DB_DIRECTORY,
   "Specifies a directory to add to the ignore list when collecting "
   "database names from the datadir. Put a blank argument to reset "
   "the list accumulated so far.", 0, 0, 0, GET_STR, REQUIRED_ARG, 
   0, 0, 0, 0, 0, 0},
  {"language", 'L',
   "Client error messages in given language. May be given as a full path. "
   "Deprecated. Use --lc-messages-dir instead.",
   &lc_messages_dir_ptr, &lc_messages_dir_ptr, 0,
   GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"lc-messages", 0,
   "Set the language used for the error messages.",
   &lc_messages, &lc_messages, 0, GET_STR, REQUIRED_ARG,
   0, 0, 0, 0, 0, 0 },
  {"lc-time-names", 0,
   "Set the language used for the month names and the days of the week.",
   &lc_time_names_name, &lc_time_names_name,
   0, GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0 },
  {"log-bin", OPT_BIN_LOG,
   "Log update queries in binary format. Optional (but strongly recommended "
   "to avoid replication problems if server's hostname changes) argument "
   "should be the chosen location for the binary log files.",
   &opt_bin_logname, &opt_bin_logname, 0, GET_STR_ALLOC,
   OPT_ARG, 0, 0, 0, 0, 0, 0},
  {"log-bin-index", 0,
   "File that holds the names for binary log files.",
   &opt_binlog_index_name, &opt_binlog_index_name, 0, GET_STR,
   REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"relay-log-index", 0,
   "File that holds the names for relay log files.",
   &opt_relaylog_index_name, &opt_relaylog_index_name, 0, GET_STR,
   REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"log-isam", OPT_ISAM_LOG, "Log all MyISAM changes to file.",
   &myisam_log_filename, &myisam_log_filename, 0, GET_STR,
   OPT_ARG, 0, 0, 0, 0, 0, 0},
  {"log-raw", 0,
   "Log to general log before any rewriting of the query. For use in debugging, not production as "
   "sensitive information may be logged.",
   &opt_general_log_raw, &opt_general_log_raw,
   0, GET_BOOL, NO_ARG, 0, 0, 1, 0, 1, 0 },
  {"log-short-format", 0,
   "Don't log extra information to update and slow-query logs.",
   &opt_short_log_format, &opt_short_log_format,
   0, GET_BOOL, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"log-tc", 0,
   "Path to transaction coordinator log (used for transactions that affect "
   "more than one storage engine, when binary log is disabled).",
   &opt_tc_log_file, &opt_tc_log_file, 0, GET_STR,
   REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
#ifdef HAVE_MMAP
  {"log-tc-size", 0, "Size of transaction coordinator log.",
   &opt_tc_log_size, &opt_tc_log_size, 0, GET_ULONG,
   REQUIRED_ARG, TC_LOG_MIN_SIZE, TC_LOG_MIN_SIZE, ULONG_MAX, 0,
   TC_LOG_PAGE_SIZE, 0},
#endif
  {"master-info-file", 0,
   "The location and name of the file that remembers the master and where "
   "the I/O replication thread is in the master's binlogs.",
   &master_info_file, &master_info_file, 0, GET_STR,
   REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"master-retry-count", OPT_MASTER_RETRY_COUNT,
   "The number of tries the slave will make to connect to the master before giving up. "
   "Deprecated option, use 'CHANGE MASTER TO master_retry_count = <num>' instead.",
   &master_retry_count, &master_retry_count, 0, GET_ULONG,
   REQUIRED_ARG, 3600*24, 0, 0, 0, 0, 0},
#ifdef HAVE_REPLICATION
  {"max-binlog-dump-events", 0,
   "Option used by mysql-test for debugging and testing of replication.",
   &max_binlog_dump_events, &max_binlog_dump_events, 0,
   GET_INT, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
#endif /* HAVE_REPLICATION */
  {"memlock", 0, "Lock mysqld in memory.", &locked_in_memory,
   &locked_in_memory, 0, GET_BOOL, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"old-style-user-limits", 0,
   "Enable old-style user limits (before 5.0.3, user resources were counted "
   "per each user+host vs. per account).",
   &opt_old_style_user_limits, &opt_old_style_user_limits,
   0, GET_BOOL, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"port-open-timeout", 0,
   "Maximum time in seconds to wait for the port to become free. "
   "(Default: No wait).", &mysqld_port_timeout, &mysqld_port_timeout, 0,
   GET_UINT, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"replicate-do-db", OPT_REPLICATE_DO_DB,
   "Tells the slave thread to restrict replication to the specified database. "
   "To specify more than one database, use the directive multiple times, "
   "once for each database. Note that this will only work if you do not use "
   "cross-database queries such as UPDATE some_db.some_table SET foo='bar' "
   "while having selected a different or no database. If you need cross "
   "database updates to work, make sure you have 3.23.28 or later, and use "
   "replicate-wild-do-table=db_name.%.",
   0, 0, 0, GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"replicate-do-table", OPT_REPLICATE_DO_TABLE,
   "Tells the slave thread to restrict replication to the specified table. "
   "To specify more than one table, use the directive multiple times, once "
   "for each table. This will work for cross-database updates, in contrast "
   "to replicate-do-db.", 0, 0, 0, GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"replicate-ignore-db", OPT_REPLICATE_IGNORE_DB,
   "Tells the slave thread to not replicate to the specified database. To "
   "specify more than one database to ignore, use the directive multiple "
   "times, once for each database. This option will not work if you use "
   "cross database updates. If you need cross database updates to work, "
   "make sure you have 3.23.28 or later, and use replicate-wild-ignore-"
   "table=db_name.%. ", 0, 0, 0, GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"replicate-ignore-table", OPT_REPLICATE_IGNORE_TABLE,
   "Tells the slave thread to not replicate to the specified table. To specify "
   "more than one table to ignore, use the directive multiple times, once for "
   "each table. This will work for cross-database updates, in contrast to "
   "replicate-ignore-db.", 0, 0, 0, GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"replicate-rewrite-db", OPT_REPLICATE_REWRITE_DB,
   "Updates to a database with a different name than the original. Example: "
   "replicate-rewrite-db=master_db_name->slave_db_name.",
   0, 0, 0, GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
#ifdef HAVE_REPLICATION
  {"replicate-same-server-id", 0,
   "In replication, if set to 1, do not skip events having our server id. "
   "Default value is 0 (to break infinite loops in circular replication). "
   "Can't be set to 1 if --log-slave-updates is used.",
   &replicate_same_server_id, &replicate_same_server_id,
   0, GET_BOOL, NO_ARG, 0, 0, 0, 0, 0, 0},
#endif
  {"replicate-wild-do-table", OPT_REPLICATE_WILD_DO_TABLE,
   "Tells the slave thread to restrict replication to the tables that match "
   "the specified wildcard pattern. To specify more than one table, use the "
   "directive multiple times, once for each table. This will work for cross-"
   "database updates. Example: replicate-wild-do-table=foo%.bar% will "
   "replicate only updates to tables in all databases that start with foo "
   "and whose table names start with bar.",
   0, 0, 0, GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"replicate-wild-ignore-table", OPT_REPLICATE_WILD_IGNORE_TABLE,
   "Tells the slave thread to not replicate to the tables that match the "
   "given wildcard pattern. To specify more than one table to ignore, use "
   "the directive multiple times, once for each table. This will work for "
   "cross-database updates. Example: replicate-wild-ignore-table=foo%.bar% "
   "will not do updates to tables in databases that start with foo and whose "
   "table names start with bar.",
   0, 0, 0, GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"safe-user-create", 0,
   "Don't allow new user creation by the user who has no write privileges to the mysql.user table.",
   &opt_safe_user_create, &opt_safe_user_create, 0, GET_BOOL,
   NO_ARG, 0, 0, 0, 0, 0, 0},
  {"show-slave-auth-info", 0,
   "Show user and password in SHOW SLAVE HOSTS on this master.",
   &opt_show_slave_auth_info, &opt_show_slave_auth_info, 0,
   GET_BOOL, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"skip-host-cache", OPT_SKIP_HOST_CACHE, "Don't cache host names.", 0, 0, 0,
   GET_NO_ARG, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"skip-new", OPT_SKIP_NEW, "Don't use new, possibly wrong routines.",
   0, 0, 0, GET_NO_ARG, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"skip-slave-start", 0,
   "If set, slave is not autostarted.", &opt_skip_slave_start,
   &opt_skip_slave_start, 0, GET_BOOL, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"skip-stack-trace", OPT_SKIP_STACK_TRACE,
   "Don't print a stack trace on failure.", 0, 0, 0, GET_NO_ARG, NO_ARG, 0, 0,
   0, 0, 0, 0},
#if defined(_WIN32) && !defined(EMBEDDED_LIBRARY)
  {"slow-start-timeout", 0,
   "Maximum number of milliseconds that the service control manager should wait "
   "before trying to kill the windows service during startup"
   "(Default: 15000).", &slow_start_timeout, &slow_start_timeout, 0,
   GET_ULONG, REQUIRED_ARG, 15000, 0, 0, 0, 0, 0},
#endif
#ifdef HAVE_REPLICATION
  {"sporadic-binlog-dump-fail", 0,
   "Option used by mysql-test for debugging and testing of replication.",
   &opt_sporadic_binlog_dump_fail,
   &opt_sporadic_binlog_dump_fail, 0, GET_BOOL, NO_ARG, 0, 0, 0, 0, 0,
   0},
#endif /* HAVE_REPLICATION */
#ifdef HAVE_OPENSSL
  {"ssl", 0,
   "Enable SSL for connection (automatically enabled with other flags).",
   &opt_use_ssl, &opt_use_ssl, 0, GET_BOOL, OPT_ARG, 0, 0, 0,
   0, 0, 0},
#endif
#ifdef _WIN32
  {"standalone", 0,
  "Dummy option to start as a standalone program (NT).", 0, 0, 0, GET_NO_ARG,
   NO_ARG, 0, 0, 0, 0, 0, 0},
#endif
  {"symbolic-links", 's', "Enable symbolic link support.",
   &my_enable_symlinks, &my_enable_symlinks, 0, GET_BOOL, NO_ARG,
   1, 0, 0, 0, 0, 0},
  {"sysdate-is-now", 0,
   "Non-default option to alias SYSDATE() to NOW() to make it safe-replicable. "
   "Since 5.0, SYSDATE() returns a `dynamic' value different for different "
   "invocations, even within the same statement.",
   &global_system_variables.sysdate_is_now,
   0, 0, GET_BOOL, NO_ARG, 0, 0, 1, 0, 1, 0},
  {"tc-heuristic-recover", 0,
   "Decision to use in heuristic recover process. Possible values are COMMIT "
   "or ROLLBACK.", &tc_heuristic_recover, &tc_heuristic_recover,
   &tc_heuristic_recover_typelib, GET_ENUM, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
#if defined(ENABLED_DEBUG_SYNC)
  {"debug-sync-timeout", OPT_DEBUG_SYNC_TIMEOUT,
   "Enable the debug sync facility "
   "and optionally specify a default wait timeout in seconds. "
   "A zero value keeps the facility disabled.",
   &opt_debug_sync_timeout, 0,
   0, GET_UINT, OPT_ARG, 0, 0, UINT_MAX, 0, 0, 0},
#endif /* defined(ENABLED_DEBUG_SYNC) */
  {"temp-pool", 0,
#if defined(__linux__)
   "Using this option will cause most temporary files created to use a small "
   "set of names, rather than a unique name for each new file.",
#else
   "This option is ignored on this OS.",
#endif
   &use_temp_pool, &use_temp_pool, 0, GET_BOOL, NO_ARG, 1,
   0, 0, 0, 0, 0},
  {"transaction-isolation", 0,
   "Default transaction isolation level.",
   &global_system_variables.tx_isolation,
   &global_system_variables.tx_isolation, &tx_isolation_typelib,
   GET_ENUM, REQUIRED_ARG, ISO_REPEATABLE_READ, 0, 0, 0, 0, 0},
  {"transaction-read-only", 0,
   "Default transaction access mode. "
   "True if transactions are read-only.",
   &global_system_variables.tx_read_only,
   &global_system_variables.tx_read_only, 0,
   GET_BOOL, OPT_ARG, 0, 0, 0, 0, 0, 0},
  {"user", 'u', "Run mysqld daemon as user.", 0, 0, 0, GET_STR, REQUIRED_ARG,
   0, 0, 0, 0, 0, 0},
  {"plugin-load", OPT_PLUGIN_LOAD,
   "Optional semicolon-separated list of plugins to load, where each plugin is "
   "identified as name=library, where name is the plugin name and library "
   "is the plugin library in plugin_dir.",
   0, 0, 0,
   GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"plugin-load-add", OPT_PLUGIN_LOAD_ADD,
   "Optional semicolon-separated list of plugins to load, where each plugin is "
   "identified as name=library, where name is the plugin name and library "
   "is the plugin library in plugin_dir. This option adds to the list "
   "speficied by --plugin-load in an incremental way. "
   "Multiple --plugin-load-add are supported.",
   0, 0, 0,
   GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {0, 0, 0, 0, 0, 0, GET_NO_ARG, NO_ARG, 0, 0, 0, 0, 0, 0}
};


static int show_queries(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONGLONG;
  var->value= (char *)&thd->query_id;
  return 0;
}


static int show_net_compression(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_MY_BOOL;
  var->value= (char *)&thd->net.compress;
  return 0;
}

static int show_starttime(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONGLONG;
  var->value= buff;
  *((longlong *)buff)= (longlong) (thd->query_start() - server_start_time);
  return 0;
}

static int show_num_thread_running(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONGLONG;
  var->value= buff;
  long long *value= reinterpret_cast<long long*>(buff);
  *value= static_cast<long long>(Global_THD_manager::get_instance()->
                                 get_num_thread_running());
  return 0;
}


static int show_num_thread_created(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONG;
  var->value= buff;
  long *value= reinterpret_cast<long*>(buff);
  *value= static_cast<long>(Global_THD_manager::get_instance()->
                            get_num_thread_created());
  return 0;
}

static int show_thread_id_count(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONG;
  var->value= buff;
  long *value= reinterpret_cast<long*>(buff);
  *value= static_cast<long>(Global_THD_manager::get_instance()->
                            get_thread_id());
  return 0;
}


#ifndef EMBEDDED_LIBRARY
static int show_aborted_connects(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONG;
  var->value= buff;
  long *value= reinterpret_cast<long*>(buff);
  *value= static_cast<long>(Connection_handler_manager::get_instance()->
                            aborted_connects());
  return 0;
}


static int show_connection_errors_max_connection(THD *thd, SHOW_VAR *var,
                                                 char *buff)
{
  var->type= SHOW_LONG;
  var->value= buff;
  long *value= reinterpret_cast<long*>(buff);
  *value= static_cast<long>(Connection_handler_manager::get_instance()->
                            connection_errors_max_connection());
  return 0;
}

static int show_connection_errors_select(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONG;
  var->value= buff;
  long *value= reinterpret_cast<long*>(buff);
  *value=
    static_cast<long>(Mysqld_socket_listener::get_connection_errors_select());
  return 0;
}

static int show_connection_errors_accept(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONG;
  var->value= buff;
  long *value= reinterpret_cast<long*>(buff);
  *value=
    static_cast<long>(Mysqld_socket_listener::get_connection_errors_accept());
  return 0;
}

static int show_connection_errors_tcpwrap(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONG;
  var->value= buff;
  long *value= reinterpret_cast<long*>(buff);
  *value=
    static_cast<long>(Mysqld_socket_listener::get_connection_errors_tcpwrap());
  return 0;
}
#endif


#ifdef ENABLED_PROFILING
static int show_flushstatustime(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONGLONG;
  var->value= buff;
  *((longlong *)buff)= (longlong) (thd->query_start() - flush_status_time);
  return 0;
}
#endif

#ifdef HAVE_REPLICATION
static int show_slave_running(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_MY_BOOL;
  var->value= buff;
  *((my_bool *)buff)= (my_bool) (active_mi &&
                                 active_mi->slave_running == MYSQL_SLAVE_RUN_CONNECT &&
                                 active_mi->rli->slave_running);
  return 0;
}

static int show_slave_retried_trans(THD *thd, SHOW_VAR *var, char *buff)
{
  /*
    TODO: with multimaster, have one such counter per line in
    SHOW SLAVE STATUS, and have the sum over all lines here.
  */
  if (active_mi)
  {
    var->type= SHOW_LONG;
    var->value= buff;
    *((long *)buff)= (long)active_mi->rli->retried_trans;
  }
  else
    var->type= SHOW_UNDEF;
  return 0;
}

static int show_slave_received_heartbeats(THD *thd, SHOW_VAR *var, char *buff)
{
  if (active_mi)
  {
    var->type= SHOW_LONGLONG;
    var->value= buff;
    *((longlong *)buff)= active_mi->received_heartbeats;
  }
  else
    var->type= SHOW_UNDEF;
  return 0;
}

static int show_slave_last_heartbeat(THD *thd, SHOW_VAR *var, char *buff)
{
  MYSQL_TIME received_heartbeat_time;
  if (active_mi)
  {
    var->type= SHOW_CHAR;
    var->value= buff;
    if (active_mi->last_heartbeat == 0)
      buff[0]='\0';
    else
    {
      thd->variables.time_zone->gmt_sec_to_TIME(&received_heartbeat_time, 
        active_mi->last_heartbeat);
      my_datetime_to_str(&received_heartbeat_time, buff, 0);
    }
  }
  else
    var->type= SHOW_UNDEF;
  return 0;
}

static int show_heartbeat_period(THD *thd, SHOW_VAR *var, char *buff)
{
  DEBUG_SYNC(thd, "dsync_show_heartbeat_period");
  if (active_mi)
  {
    var->type= SHOW_CHAR;
    var->value= buff;
    sprintf(buff, "%.3f", active_mi->heartbeat_period);
  }
  else
    var->type= SHOW_UNDEF;
  return 0;
}

#ifndef DBUG_OFF
static int show_slave_rows_last_search_algorithm_used(THD *thd, SHOW_VAR *var, char *buff)
{
  uint res= slave_rows_last_search_algorithm_used;
  const char* s= ((res == Rows_log_event::ROW_LOOKUP_TABLE_SCAN) ? "TABLE_SCAN" :
                  ((res == Rows_log_event::ROW_LOOKUP_HASH_SCAN) ? "HASH_SCAN" : 
                   "INDEX_SCAN"));

  var->type= SHOW_CHAR;
  var->value= buff;
  sprintf(buff, "%s", s);

  return 0;
}
#endif

#endif /* HAVE_REPLICATION */

static int show_open_tables(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONG;
  var->value= buff;
  *((long *)buff)= (long)table_cache_manager.cached_tables();
  return 0;
}

static int show_prepared_stmt_count(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONG;
  var->value= buff;
  mysql_mutex_lock(&LOCK_prepared_stmt_count);
  *((long *)buff)= (long)prepared_stmt_count;
  mysql_mutex_unlock(&LOCK_prepared_stmt_count);
  return 0;
}

static int show_table_definitions(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONG;
  var->value= buff;
  *((long *)buff)= (long)cached_table_definitions();
  return 0;
}

#if defined(HAVE_OPENSSL) && !defined(EMBEDDED_LIBRARY)
/* Functions relying on CTX */
static int show_ssl_ctx_sess_accept(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONG;
  var->value= buff;
  *((long *)buff)= (!ssl_acceptor_fd ? 0 :
                     SSL_CTX_sess_accept(ssl_acceptor_fd->ssl_context));
  return 0;
}

static int show_ssl_ctx_sess_accept_good(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONG;
  var->value= buff;
  *((long *)buff)= (!ssl_acceptor_fd ? 0 :
                     SSL_CTX_sess_accept_good(ssl_acceptor_fd->ssl_context));
  return 0;
}

static int show_ssl_ctx_sess_connect_good(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONG;
  var->value= buff;
  *((long *)buff)= (!ssl_acceptor_fd ? 0 :
                     SSL_CTX_sess_connect_good(ssl_acceptor_fd->ssl_context));
  return 0;
}

static int show_ssl_ctx_sess_accept_renegotiate(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONG;
  var->value= buff;
  *((long *)buff)= (!ssl_acceptor_fd ? 0 :
                     SSL_CTX_sess_accept_renegotiate(ssl_acceptor_fd->ssl_context));
  return 0;
}

static int show_ssl_ctx_sess_connect_renegotiate(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONG;
  var->value= buff;
  *((long *)buff)= (!ssl_acceptor_fd ? 0 :
                     SSL_CTX_sess_connect_renegotiate(ssl_acceptor_fd->ssl_context));
  return 0;
}

static int show_ssl_ctx_sess_cb_hits(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONG;
  var->value= buff;
  *((long *)buff)= (!ssl_acceptor_fd ? 0 :
                     SSL_CTX_sess_cb_hits(ssl_acceptor_fd->ssl_context));
  return 0;
}

static int show_ssl_ctx_sess_hits(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONG;
  var->value= buff;
  *((long *)buff)= (!ssl_acceptor_fd ? 0 :
                     SSL_CTX_sess_hits(ssl_acceptor_fd->ssl_context));
  return 0;
}

static int show_ssl_ctx_sess_cache_full(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONG;
  var->value= buff;
  *((long *)buff)= (!ssl_acceptor_fd ? 0 :
                     SSL_CTX_sess_cache_full(ssl_acceptor_fd->ssl_context));
  return 0;
}

static int show_ssl_ctx_sess_misses(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONG;
  var->value= buff;
  *((long *)buff)= (!ssl_acceptor_fd ? 0 :
                     SSL_CTX_sess_misses(ssl_acceptor_fd->ssl_context));
  return 0;
}

static int show_ssl_ctx_sess_timeouts(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONG;
  var->value= buff;
  *((long *)buff)= (!ssl_acceptor_fd ? 0 :
                     SSL_CTX_sess_timeouts(ssl_acceptor_fd->ssl_context));
  return 0;
}

static int show_ssl_ctx_sess_number(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONG;
  var->value= buff;
  *((long *)buff)= (!ssl_acceptor_fd ? 0 :
                     SSL_CTX_sess_number(ssl_acceptor_fd->ssl_context));
  return 0;
}

static int show_ssl_ctx_sess_connect(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONG;
  var->value= buff;
  *((long *)buff)= (!ssl_acceptor_fd ? 0 :
                     SSL_CTX_sess_connect(ssl_acceptor_fd->ssl_context));
  return 0;
}

static int show_ssl_ctx_sess_get_cache_size(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONG;
  var->value= buff;
  *((long *)buff)= (!ssl_acceptor_fd ? 0 :
                     SSL_CTX_sess_get_cache_size(ssl_acceptor_fd->ssl_context));
  return 0;
}

static int show_ssl_ctx_get_verify_mode(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONG;
  var->value= buff;
  *((long *)buff)= (!ssl_acceptor_fd ? 0 :
                     SSL_CTX_get_verify_mode(ssl_acceptor_fd->ssl_context));
  return 0;
}

static int show_ssl_ctx_get_verify_depth(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONG;
  var->value= buff;
  *((long *)buff)= (!ssl_acceptor_fd ? 0 :
                     SSL_CTX_get_verify_depth(ssl_acceptor_fd->ssl_context));
  return 0;
}

static int show_ssl_ctx_get_session_cache_mode(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_CHAR;
  if (!ssl_acceptor_fd)
    var->value= const_cast<char*>("NONE");
  else
    switch (SSL_CTX_get_session_cache_mode(ssl_acceptor_fd->ssl_context))
    {
    case SSL_SESS_CACHE_OFF:
      var->value= const_cast<char*>("OFF"); break;
    case SSL_SESS_CACHE_CLIENT:
      var->value= const_cast<char*>("CLIENT"); break;
    case SSL_SESS_CACHE_SERVER:
      var->value= const_cast<char*>("SERVER"); break;
    case SSL_SESS_CACHE_BOTH:
      var->value= const_cast<char*>("BOTH"); break;
    case SSL_SESS_CACHE_NO_AUTO_CLEAR:
      var->value= const_cast<char*>("NO_AUTO_CLEAR"); break;
    case SSL_SESS_CACHE_NO_INTERNAL_LOOKUP:
      var->value= const_cast<char*>("NO_INTERNAL_LOOKUP"); break;
    default:
      var->value= const_cast<char*>("Unknown"); break;
    }
  return 0;
}

/*
   Functions relying on SSL
   Note: In the show_ssl_* functions, we need to check if we have a
         valid vio-object since this isn't always true, specifically
         when session_status or global_status is requested from
         inside an Event.
 */
static int show_ssl_get_version(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_CHAR;
  if( thd->vio_ok() && thd->net.vio->ssl_arg )
    var->value= const_cast<char*>(SSL_get_version((SSL*) thd->net.vio->ssl_arg));
  else
    var->value= (char *)"";
  return 0;
}

static int show_ssl_session_reused(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONG;
  var->value= buff;
  if( thd->vio_ok() && thd->net.vio->ssl_arg )
    *((long *)buff)= (long)SSL_session_reused((SSL*) thd->net.vio->ssl_arg);
  else
    *((long *)buff)= 0;
  return 0;
}

static int show_ssl_get_default_timeout(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONG;
  var->value= buff;
  if( thd->vio_ok() && thd->net.vio->ssl_arg )
    *((long *)buff)= (long)SSL_get_default_timeout((SSL*)thd->net.vio->ssl_arg);
  else
    *((long *)buff)= 0;
  return 0;
}

static int show_ssl_get_verify_mode(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONG;
  var->value= buff;
  if( thd->net.vio && thd->net.vio->ssl_arg )
    *((long *)buff)= (long)SSL_get_verify_mode((SSL*)thd->net.vio->ssl_arg);
  else
    *((long *)buff)= 0;
  return 0;
}

static int show_ssl_get_verify_depth(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_LONG;
  var->value= buff;
  if( thd->vio_ok() && thd->net.vio->ssl_arg )
    *((long *)buff)= (long)SSL_get_verify_depth((SSL*)thd->net.vio->ssl_arg);
  else
    *((long *)buff)= 0;
  return 0;
}

static int show_ssl_get_cipher(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_CHAR;
  if( thd->vio_ok() && thd->net.vio->ssl_arg )
    var->value= const_cast<char*>(SSL_get_cipher((SSL*) thd->net.vio->ssl_arg));
  else
    var->value= (char *)"";
  return 0;
}

static int show_ssl_get_cipher_list(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_CHAR;
  var->value= buff;
  if (thd->vio_ok() && thd->net.vio->ssl_arg)
  {
    int i;
    const char *p;
    char *end= buff + SHOW_VAR_FUNC_BUFF_SIZE;
    for (i=0; (p= SSL_get_cipher_list((SSL*) thd->net.vio->ssl_arg,i)) &&
               buff < end; i++)
    {
      buff= my_stpnmov(buff, p, end-buff-1);
      *buff++= ':';
    }
    if (i)
      buff--;
  }
  *buff=0;
  return 0;
}


#ifdef HAVE_YASSL

static char *
my_asn1_time_to_string(ASN1_TIME *time, char *buf, size_t len)
{
  return yaSSL_ASN1_TIME_to_string(time, buf, len);
}

#else /* openssl */

static char *
my_asn1_time_to_string(ASN1_TIME *time, char *buf, size_t len)
{
  int n_read;
  char *res= NULL;
  BIO *bio= BIO_new(BIO_s_mem());

  if (bio == NULL)
    return NULL;

  if (!ASN1_TIME_print(bio, time))
    goto end;

  n_read= BIO_read(bio, buf, (int) (len - 1));

  if (n_read > 0)
  {
    buf[n_read]= 0;
    res= buf;
  }

end:
  BIO_free(bio);
  return res;
}

#endif


/**
  Handler function for the 'ssl_get_server_not_before' variable

  @param      thd  the mysql thread structure
  @param      var  the data for the variable
  @param[out] buf  the string to put the value of the variable into

  @return          status
  @retval     0    success
*/

static int
show_ssl_get_server_not_before(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_CHAR;
  if(thd->vio_ok() && thd->net.vio->ssl_arg)
  {
    SSL *ssl= (SSL*) thd->net.vio->ssl_arg;
    X509 *cert= SSL_get_certificate(ssl);
    ASN1_TIME *not_before= X509_get_notBefore(cert);

    var->value= my_asn1_time_to_string(not_before, buff,
                                       SHOW_VAR_FUNC_BUFF_SIZE);
    if (!var->value)
      return 1;
    var->value= buff;
  }
  else
    var->value= empty_c_string;
  return 0;
}


/**
  Handler function for the 'ssl_get_server_not_after' variable

  @param      thd  the mysql thread structure
  @param      var  the data for the variable
  @param[out] buf  the string to put the value of the variable into

  @return          status
  @retval     0    success
*/

static int
show_ssl_get_server_not_after(THD *thd, SHOW_VAR *var, char *buff)
{
  var->type= SHOW_CHAR;
  if(thd->vio_ok() && thd->net.vio->ssl_arg)
  {
    SSL *ssl= (SSL*) thd->net.vio->ssl_arg;
    X509 *cert= SSL_get_certificate(ssl);
    ASN1_TIME *not_after= X509_get_notAfter(cert);

    var->value= my_asn1_time_to_string(not_after, buff,
                                       SHOW_VAR_FUNC_BUFF_SIZE);
    if (!var->value)
      return 1;
  }
  else
    var->value= empty_c_string;
  return 0;
}

#endif /* HAVE_OPENSSL && !EMBEDDED_LIBRARY */


/*
  Variables shown by SHOW STATUS in alphabetical order
*/

SHOW_VAR status_vars[]= {
  {"Aborted_clients",          (char*) &aborted_threads,        SHOW_LONG},
#ifndef EMBEDDED_LIBRARY
  {"Aborted_connects",         (char*) &show_aborted_connects,  SHOW_FUNC},
#endif
  {"Binlog_cache_disk_use",    (char*) &binlog_cache_disk_use,  SHOW_LONG},
  {"Binlog_cache_use",         (char*) &binlog_cache_use,       SHOW_LONG},
  {"Binlog_stmt_cache_disk_use",(char*) &binlog_stmt_cache_disk_use,  SHOW_LONG},
  {"Binlog_stmt_cache_use",    (char*) &binlog_stmt_cache_use,       SHOW_LONG},
  {"Bytes_received",           (char*) offsetof(STATUS_VAR, bytes_received), SHOW_LONGLONG_STATUS},
  {"Bytes_sent",               (char*) offsetof(STATUS_VAR, bytes_sent), SHOW_LONGLONG_STATUS},
  {"Com",                      (char*) com_status_vars, SHOW_ARRAY},
  {"Compression",              (char*) &show_net_compression, SHOW_FUNC},
  {"Connections",              (char*) &show_thread_id_count, SHOW_FUNC},
#ifndef EMBEDDED_LIBRARY
  {"Connection_errors_accept",   (char*) &show_connection_errors_accept, SHOW_FUNC},
  {"Connection_errors_internal", (char*) &connection_errors_internal, SHOW_LONG},
  {"Connection_errors_max_connections",
   (char*) &show_connection_errors_max_connection, SHOW_FUNC},
  {"Connection_errors_peer_address", (char*) &connection_errors_peer_addr, SHOW_LONG},
  {"Connection_errors_select",   (char*) &show_connection_errors_select, SHOW_FUNC},
  {"Connection_errors_tcpwrap",  (char*) &show_connection_errors_tcpwrap, SHOW_FUNC},
#endif
  {"Created_tmp_disk_tables",  (char*) offsetof(STATUS_VAR, created_tmp_disk_tables), SHOW_LONGLONG_STATUS},
  {"Created_tmp_files",        (char*) &my_tmp_file_created, SHOW_LONG},
  {"Created_tmp_tables",       (char*) offsetof(STATUS_VAR, created_tmp_tables), SHOW_LONGLONG_STATUS},
  {"Delayed_errors",           (char*) &delayed_insert_errors,  SHOW_LONG},
  {"Delayed_insert_threads",   (char*) &delayed_insert_threads, SHOW_LONG_NOFLUSH},
  {"Delayed_writes",           (char*) &delayed_insert_writes,  SHOW_LONG},
  {"Flush_commands",           (char*) &refresh_version,        SHOW_LONG_NOFLUSH},
  {"Handler_commit",           (char*) offsetof(STATUS_VAR, ha_commit_count), SHOW_LONGLONG_STATUS},
  {"Handler_delete",           (char*) offsetof(STATUS_VAR, ha_delete_count), SHOW_LONGLONG_STATUS},
  {"Handler_discover",         (char*) offsetof(STATUS_VAR, ha_discover_count), SHOW_LONGLONG_STATUS},
  {"Handler_external_lock",    (char*) offsetof(STATUS_VAR, ha_external_lock_count), SHOW_LONGLONG_STATUS},
  {"Handler_mrr_init",         (char*) offsetof(STATUS_VAR, ha_multi_range_read_init_count),  SHOW_LONGLONG_STATUS},
  {"Handler_prepare",          (char*) offsetof(STATUS_VAR, ha_prepare_count),  SHOW_LONGLONG_STATUS},
  {"Handler_read_first",       (char*) offsetof(STATUS_VAR, ha_read_first_count), SHOW_LONGLONG_STATUS},
  {"Handler_read_key",         (char*) offsetof(STATUS_VAR, ha_read_key_count), SHOW_LONGLONG_STATUS},
  {"Handler_read_last",        (char*) offsetof(STATUS_VAR, ha_read_last_count), SHOW_LONGLONG_STATUS},
  {"Handler_read_next",        (char*) offsetof(STATUS_VAR, ha_read_next_count), SHOW_LONGLONG_STATUS},
  {"Handler_read_prev",        (char*) offsetof(STATUS_VAR, ha_read_prev_count), SHOW_LONGLONG_STATUS},
  {"Handler_read_rnd",         (char*) offsetof(STATUS_VAR, ha_read_rnd_count), SHOW_LONGLONG_STATUS},
  {"Handler_read_rnd_next",    (char*) offsetof(STATUS_VAR, ha_read_rnd_next_count), SHOW_LONGLONG_STATUS},
  {"Handler_rollback",         (char*) offsetof(STATUS_VAR, ha_rollback_count), SHOW_LONGLONG_STATUS},
  {"Handler_savepoint",        (char*) offsetof(STATUS_VAR, ha_savepoint_count), SHOW_LONGLONG_STATUS},
  {"Handler_savepoint_rollback",(char*) offsetof(STATUS_VAR, ha_savepoint_rollback_count), SHOW_LONGLONG_STATUS},
  {"Handler_update",           (char*) offsetof(STATUS_VAR, ha_update_count), SHOW_LONGLONG_STATUS},
  {"Handler_write",            (char*) offsetof(STATUS_VAR, ha_write_count), SHOW_LONGLONG_STATUS},
  {"Key_blocks_not_flushed",   (char*) offsetof(KEY_CACHE, global_blocks_changed), SHOW_KEY_CACHE_LONG},
  {"Key_blocks_unused",        (char*) offsetof(KEY_CACHE, blocks_unused), SHOW_KEY_CACHE_LONG},
  {"Key_blocks_used",          (char*) offsetof(KEY_CACHE, blocks_used), SHOW_KEY_CACHE_LONG},
  {"Key_read_requests",        (char*) offsetof(KEY_CACHE, global_cache_r_requests), SHOW_KEY_CACHE_LONGLONG},
  {"Key_reads",                (char*) offsetof(KEY_CACHE, global_cache_read), SHOW_KEY_CACHE_LONGLONG},
  {"Key_write_requests",       (char*) offsetof(KEY_CACHE, global_cache_w_requests), SHOW_KEY_CACHE_LONGLONG},
  {"Key_writes",               (char*) offsetof(KEY_CACHE, global_cache_write), SHOW_KEY_CACHE_LONGLONG},
  {"Last_query_cost",          (char*) offsetof(STATUS_VAR, last_query_cost), SHOW_DOUBLE_STATUS},
  {"Last_query_partial_plans", (char*) offsetof(STATUS_VAR, last_query_partial_plans), SHOW_LONGLONG_STATUS},
  {"Max_used_connections",     (char*) &Connection_handler_manager::max_used_connections, SHOW_LONG},
  {"Max_statement_time_exceeded",   (char*) offsetof(STATUS_VAR, max_statement_time_exceeded), SHOW_LONG_STATUS},
  {"Max_statement_time_set",        (char*) offsetof(STATUS_VAR, max_statement_time_set), SHOW_LONG_STATUS},
  {"Max_statement_time_set_failed", (char*) offsetof(STATUS_VAR, max_statement_time_set_failed), SHOW_LONG_STATUS},
  {"Not_flushed_delayed_rows", (char*) &delayed_rows_in_use,    SHOW_LONG_NOFLUSH},
  {"Open_files",               (char*) &my_file_opened,         SHOW_LONG_NOFLUSH},
  {"Open_streams",             (char*) &my_stream_opened,       SHOW_LONG_NOFLUSH},
  {"Open_table_definitions",   (char*) &show_table_definitions, SHOW_FUNC},
  {"Open_tables",              (char*) &show_open_tables,       SHOW_FUNC},
  {"Opened_files",             (char*) &my_file_total_opened, SHOW_LONG_NOFLUSH},
  {"Opened_tables",            (char*) offsetof(STATUS_VAR, opened_tables), SHOW_LONGLONG_STATUS},
  {"Opened_table_definitions", (char*) offsetof(STATUS_VAR, opened_shares), SHOW_LONGLONG_STATUS},
  {"Prepared_stmt_count",      (char*) &show_prepared_stmt_count, SHOW_FUNC},
  {"Qcache_free_blocks",       (char*) &query_cache.free_memory_blocks, SHOW_LONG_NOFLUSH},
  {"Qcache_free_memory",       (char*) &query_cache.free_memory, SHOW_LONG_NOFLUSH},
  {"Qcache_hits",              (char*) &query_cache.hits,       SHOW_LONG},
  {"Qcache_inserts",           (char*) &query_cache.inserts,    SHOW_LONG},
  {"Qcache_lowmem_prunes",     (char*) &query_cache.lowmem_prunes, SHOW_LONG},
  {"Qcache_not_cached",        (char*) &query_cache.refused,    SHOW_LONG},
  {"Qcache_queries_in_cache",  (char*) &query_cache.queries_in_cache, SHOW_LONG_NOFLUSH},
  {"Qcache_total_blocks",      (char*) &query_cache.total_blocks, SHOW_LONG_NOFLUSH},
  {"Queries",                  (char*) &show_queries,            SHOW_FUNC},
  {"Questions",                (char*) offsetof(STATUS_VAR, questions), SHOW_LONGLONG_STATUS},
  {"Select_full_join",         (char*) offsetof(STATUS_VAR, select_full_join_count), SHOW_LONGLONG_STATUS},
  {"Select_full_range_join",   (char*) offsetof(STATUS_VAR, select_full_range_join_count), SHOW_LONGLONG_STATUS},
  {"Select_range",             (char*) offsetof(STATUS_VAR, select_range_count), SHOW_LONGLONG_STATUS},
  {"Select_range_check",       (char*) offsetof(STATUS_VAR, select_range_check_count), SHOW_LONGLONG_STATUS},
  {"Select_scan",	       (char*) offsetof(STATUS_VAR, select_scan_count), SHOW_LONGLONG_STATUS},
  {"Slave_open_temp_tables",   (char*) &slave_open_temp_tables, SHOW_INT},
#ifdef HAVE_REPLICATION
  {"Slave_retried_transactions",(char*) &show_slave_retried_trans, SHOW_FUNC},
  {"Slave_heartbeat_period",   (char*) &show_heartbeat_period, SHOW_FUNC},
  {"Slave_received_heartbeats",(char*) &show_slave_received_heartbeats, SHOW_FUNC},
  {"Slave_last_heartbeat",     (char*) &show_slave_last_heartbeat, SHOW_FUNC},
#ifndef DBUG_OFF
  {"Slave_rows_last_search_algorithm_used",(char*) &show_slave_rows_last_search_algorithm_used, SHOW_FUNC},
#endif
  {"Slave_running",            (char*) &show_slave_running,     SHOW_FUNC},
#endif
#ifndef EMBEDDED_LIBRARY
  {"Slow_launch_threads",      (char*) &Per_thread_connection_handler::slow_launch_threads, SHOW_LONG},
#endif
  {"Slow_queries",             (char*) offsetof(STATUS_VAR, long_query_count), SHOW_LONGLONG_STATUS},
  {"Sort_merge_passes",        (char*) offsetof(STATUS_VAR, filesort_merge_passes), SHOW_LONGLONG_STATUS},
  {"Sort_range",               (char*) offsetof(STATUS_VAR, filesort_range_count), SHOW_LONGLONG_STATUS},
  {"Sort_rows",                (char*) offsetof(STATUS_VAR, filesort_rows), SHOW_LONGLONG_STATUS},
  {"Sort_scan",                (char*) offsetof(STATUS_VAR, filesort_scan_count), SHOW_LONGLONG_STATUS},
#ifdef HAVE_OPENSSL
#ifndef EMBEDDED_LIBRARY
  {"Ssl_accept_renegotiates",  (char*) &show_ssl_ctx_sess_accept_renegotiate, SHOW_FUNC},
  {"Ssl_accepts",              (char*) &show_ssl_ctx_sess_accept, SHOW_FUNC},
  {"Ssl_callback_cache_hits",  (char*) &show_ssl_ctx_sess_cb_hits, SHOW_FUNC},
  {"Ssl_cipher",               (char*) &show_ssl_get_cipher, SHOW_FUNC},
  {"Ssl_cipher_list",          (char*) &show_ssl_get_cipher_list, SHOW_FUNC},
  {"Ssl_client_connects",      (char*) &show_ssl_ctx_sess_connect, SHOW_FUNC},
  {"Ssl_connect_renegotiates", (char*) &show_ssl_ctx_sess_connect_renegotiate, SHOW_FUNC},
  {"Ssl_ctx_verify_depth",     (char*) &show_ssl_ctx_get_verify_depth, SHOW_FUNC},
  {"Ssl_ctx_verify_mode",      (char*) &show_ssl_ctx_get_verify_mode, SHOW_FUNC},
  {"Ssl_default_timeout",      (char*) &show_ssl_get_default_timeout, SHOW_FUNC},
  {"Ssl_finished_accepts",     (char*) &show_ssl_ctx_sess_accept_good, SHOW_FUNC},
  {"Ssl_finished_connects",    (char*) &show_ssl_ctx_sess_connect_good, SHOW_FUNC},
  {"Ssl_session_cache_hits",   (char*) &show_ssl_ctx_sess_hits, SHOW_FUNC},
  {"Ssl_session_cache_misses", (char*) &show_ssl_ctx_sess_misses, SHOW_FUNC},
  {"Ssl_session_cache_mode",   (char*) &show_ssl_ctx_get_session_cache_mode, SHOW_FUNC},
  {"Ssl_session_cache_overflows", (char*) &show_ssl_ctx_sess_cache_full, SHOW_FUNC},
  {"Ssl_session_cache_size",   (char*) &show_ssl_ctx_sess_get_cache_size, SHOW_FUNC},
  {"Ssl_session_cache_timeouts", (char*) &show_ssl_ctx_sess_timeouts, SHOW_FUNC},
  {"Ssl_sessions_reused",      (char*) &show_ssl_session_reused, SHOW_FUNC},
  {"Ssl_used_session_cache_entries",(char*) &show_ssl_ctx_sess_number, SHOW_FUNC},
  {"Ssl_verify_depth",         (char*) &show_ssl_get_verify_depth, SHOW_FUNC},
  {"Ssl_verify_mode",          (char*) &show_ssl_get_verify_mode, SHOW_FUNC},
  {"Ssl_version",              (char*) &show_ssl_get_version, SHOW_FUNC},
  {"Ssl_server_not_before",    (char*) &show_ssl_get_server_not_before,
    SHOW_FUNC},
  {"Ssl_server_not_after",     (char*) &show_ssl_get_server_not_after,
    SHOW_FUNC},
#ifndef HAVE_YASSL
  {"Rsa_public_key",           (char*) &show_rsa_public_key, SHOW_FUNC},
#endif
#endif
#endif /* HAVE_OPENSSL */
  {"Table_locks_immediate",    (char*) &locks_immediate,        SHOW_LONG},
  {"Table_locks_waited",       (char*) &locks_waited,           SHOW_LONG},
  {"Table_open_cache_hits",    (char*) offsetof(STATUS_VAR, table_open_cache_hits), SHOW_LONGLONG_STATUS},
  {"Table_open_cache_misses",  (char*) offsetof(STATUS_VAR, table_open_cache_misses), SHOW_LONGLONG_STATUS},
  {"Table_open_cache_overflows",(char*) offsetof(STATUS_VAR, table_open_cache_overflows), SHOW_LONGLONG_STATUS},
#ifdef HAVE_MMAP
  {"Tc_log_max_pages_used",    (char*) &tc_log_max_pages_used,  SHOW_LONG},
  {"Tc_log_page_size",         (char*) &tc_log_page_size,       SHOW_LONG_NOFLUSH},
  {"Tc_log_page_waits",        (char*) &tc_log_page_waits,      SHOW_LONG},
#endif
#ifndef EMBEDDED_LIBRARY
  {"Threads_cached",           (char*) &Per_thread_connection_handler::blocked_pthread_count,
   SHOW_LONG_NOFLUSH},
#endif
  {"Threads_connected",        (char*) &Connection_handler_manager::connection_count,
   SHOW_INT},
  {"Threads_created",          (char*) &show_num_thread_created,   SHOW_FUNC},
  {"Threads_running",          (char*) &show_num_thread_running,   SHOW_FUNC},
  {"Uptime",                   (char*) &show_starttime,         SHOW_FUNC},
#ifdef ENABLED_PROFILING
  {"Uptime_since_flush_status",(char*) &show_flushstatustime,   SHOW_FUNC},
#endif
  {NullS, NullS, SHOW_LONG}
};

void add_terminator(vector<my_option> *options)
{
  my_option empty_element=
    {0, 0, 0, 0, 0, 0, GET_NO_ARG, NO_ARG, 0, 0, 0, 0, 0, 0};
  options->push_back(empty_element);
}

#ifndef EMBEDDED_LIBRARY
static void print_version(void)
{
  set_server_version();

  printf("%s  Ver %s for %s on %s (%s)\n",my_progname,
   server_version,SYSTEM_TYPE,MACHINE_TYPE, MYSQL_COMPILATION_COMMENT);
}

/** Compares two options' names, treats - and _ the same */
static bool operator<(const my_option &a, const my_option &b)
{
  const char *sa= a.name;
  const char *sb= b.name;
  for (; *sa || *sb; sa++, sb++)
  {
    if (*sa < *sb)
    {
      if (*sa == '-' && *sb == '_')
        continue;
      else
        return true;
    }
    if (*sa > *sb)
    {
      if (*sa == '_' && *sb == '-')
        continue;
      else
        return false;
    }
  }
  DBUG_ASSERT(a.name == b.name);
  return false;
}

static void print_help()
{
  MEM_ROOT mem_root;
  init_alloc_root(key_memory_help, &mem_root, 4096, 4096);

  all_options.pop_back();
  sys_var_add_options(&all_options, sys_var::PARSE_EARLY);
  for (my_option *opt= my_long_early_options;
       opt->name != NULL;
       opt++)
  {
    all_options.push_back(*opt);
  }
  add_plugin_options(&all_options, &mem_root);
  std::sort(all_options.begin(), all_options.end(), std::less<my_option>());
  add_terminator(&all_options);

  my_print_help(&all_options[0]);
  my_print_variables(&all_options[0]);

  free_root(&mem_root, MYF(0));
  vector<my_option>().swap(all_options);  // Deletes the vector contents.
}

static void usage(void)
{
  DBUG_ENTER("usage");
  if (!(default_charset_info= get_charset_by_csname(default_character_set_name,
                     MY_CS_PRIMARY,
               MYF(MY_WME))))
    exit(1);
  if (!default_collation_name)
    default_collation_name= (char*) default_charset_info->name;
  print_version();
  puts(ORACLE_WELCOME_COPYRIGHT_NOTICE("2000"));
  puts("Starts the MySQL database server.\n");
  printf("Usage: %s [OPTIONS]\n", my_progname);
  if (!opt_verbose)
    puts("\nFor more help options (several pages), use mysqld --verbose --help.");
  else
  {
#ifdef _WIN32
  puts("NT and Win32 specific options:\n\
  --install                     Install the default service (NT).\n\
  --install-manual              Install the default service started manually (NT).\n\
  --install service_name        Install an optional service (NT).\n\
  --install-manual service_name Install an optional service started manually (NT).\n\
  --remove                      Remove the default service from the service list (NT).\n\
  --remove service_name         Remove the service_name from the service list (NT).\n\
  --enable-named-pipe           Only to be used for the default server (NT).\n\
  --standalone                  Dummy option to start as a standalone server (NT).\
");
  puts("");
#endif
  print_defaults(MYSQL_CONFIG_NAME,load_default_groups);
  puts("");
  set_ports();

  /* Print out all the options including plugin supplied options */
  print_help();

  if (! plugins_are_initialized)
  {
    puts("\n\
Plugins have parameters that are not reflected in this list\n\
because execution stopped before plugins were initialized.");
  }

  puts("\n\
To see what values a running MySQL server is using, type\n\
'mysqladmin variables' instead of 'mysqld --verbose --help'.");
  }
  DBUG_VOID_RETURN;
}
#endif /*!EMBEDDED_LIBRARY*/

/**
  Initialize MySQL global variables to default values.

  @note
    The reason to set a lot of global variables to zero is to allow one to
    restart the embedded server with a clean environment
    It's also needed on some exotic platforms where global variables are
    not set to 0 when a program starts.

    We don't need to set variables refered to in my_long_options
    as these are initialized by my_getopt.
*/

static int mysql_init_variables(void)
{
  /* Things reset to zero */
  opt_skip_slave_start= opt_reckless_slave = 0;
  mysql_home[0]= pidfile_name[0]= log_error_file[0]= 0;
  myisam_test_invalid_symlink= test_if_data_home_dir;
  opt_general_log= opt_slow_log= false;
  opt_bin_log= 0;
  opt_disable_networking= opt_skip_show_db=0;
  opt_skip_name_resolve= 0;
  opt_ignore_builtin_innodb= 0;
  opt_general_logname= opt_update_logname= opt_binlog_index_name= opt_slow_logname= NULL;
  opt_tc_log_file= (char *)"tc.log";      // no hostname in tc_log file name !
  opt_secure_auth= 0;
  opt_secure_file_priv= NULL;
  opt_myisam_log= 0;
  mqh_used= 0;
  kill_in_progress= 0;
  cleanup_done= 0;
  server_id_supplied= false;
  test_flags= select_errors= dropping_tables= ha_open_options=0;
  slave_open_temp_tables= 0;
  opt_endinfo= using_udf_functions= 0;
  opt_using_transactions= 0;
  abort_loop= 0;
  grant_option= 0;
  aborted_threads= 0;
  delayed_insert_threads= delayed_insert_writes= delayed_rows_in_use= 0;
  delayed_insert_errors= 0;
  specialflag= 0;
  binlog_cache_use=  binlog_cache_disk_use= 0;
  mysqld_user= mysqld_chroot= opt_init_file= opt_bin_logname = 0;
  prepared_stmt_count= 0;
  mysqld_unix_port= opt_mysql_tmpdir= my_bind_addr_str= NullS;
  memset(&mysql_tmpdir_list, 0, sizeof(mysql_tmpdir_list));
  memset(&global_status_var, 0, sizeof(global_status_var));
  opt_large_pages= 0;
  opt_super_large_pages= 0;
#if defined(ENABLED_DEBUG_SYNC)
  opt_debug_sync_timeout= 0;
#endif /* defined(ENABLED_DEBUG_SYNC) */
  key_map_full.set_all();
  server_uuid[0]= 0;

  /* Character sets */
  system_charset_info= &my_charset_utf8_general_ci;
  files_charset_info= &my_charset_utf8_general_ci;
  national_charset_info= &my_charset_utf8_general_ci;
  table_alias_charset= &my_charset_bin;
  character_set_filesystem= &my_charset_bin;

  opt_specialflag= SPECIAL_ENGLISH;
  mysql_home_ptr= mysql_home;
  pidfile_name_ptr= pidfile_name;
  log_error_file_ptr= log_error_file;
  lc_messages_dir_ptr= lc_messages_dir;
  protocol_version= PROTOCOL_VERSION;
  what_to_log= ~ (1L << (uint) COM_TIME);
  refresh_version= 1L;  /* Increments on each reload */
  global_query_id= 1L;
  my_atomic_rwlock_init(&opt_binlog_max_flush_queue_time_lock);
  my_atomic_rwlock_init(&global_query_id_lock);
  my_stpcpy(server_version, MYSQL_SERVER_VERSION);
  key_caches.empty();
  if (!(dflt_key_cache= get_or_create_key_cache(default_key_cache_base.str,
                                                default_key_cache_base.length)))
  {
    sql_print_error("Cannot allocate the keycache");
    return 1;
  }
  /* set key_cache_hash.default_value = dflt_key_cache */
  multi_keycache_init();

  /* Set directory paths */
  mysql_real_data_home_len=
    strmake(mysql_real_data_home, get_relative_path(MYSQL_DATADIR),
            sizeof(mysql_real_data_home)-1) - mysql_real_data_home;
  /* Replication parameters */
  master_info_file= (char*) "master.info",
    relay_log_info_file= (char*) "relay-log.info";
  report_user= report_password = report_host= 0;  /* TO BE DELETED */
  opt_relay_logname= opt_relaylog_index_name= 0;
  log_bin_basename= NULL;
  log_bin_index= NULL;

  /* Handler variables */
  total_ha= 0;
  total_ha_2pc= 0;
  /* Variables in libraries */
  charsets_dir= 0;
  default_character_set_name= (char*) MYSQL_DEFAULT_CHARSET_NAME;
  default_collation_name= compiled_default_collation_name;
  character_set_filesystem_name= (char*) "binary";
  lc_messages= (char*) "en_US";
  lc_time_names_name= (char*) "en_US";

  /* Variables that depends on compile options */
#ifndef DBUG_OFF
  default_dbug_option=IF_WIN("d:t:i:O,\\mysqld.trace",
           "d:t:i:o,/tmp/mysqld.trace");
#endif
  opt_error_log= IF_WIN(1,0);
#ifdef ENABLED_PROFILING
    have_profiling = SHOW_OPTION_YES;
#else
    have_profiling = SHOW_OPTION_NO;
#endif

#ifdef HAVE_OPENSSL
  have_ssl=SHOW_OPTION_YES;
#else
  have_ssl=SHOW_OPTION_NO;
#endif

  have_symlink= SHOW_OPTION_YES;

#ifdef HAVE_DLOPEN
  have_dlopen=SHOW_OPTION_YES;
#else
  have_dlopen=SHOW_OPTION_NO;
#endif

  have_query_cache=SHOW_OPTION_YES;

  have_geometry=SHOW_OPTION_YES;

  have_rtree_keys=SHOW_OPTION_YES;

#ifdef HAVE_CRYPT
  have_crypt=SHOW_OPTION_YES;
#else
  have_crypt=SHOW_OPTION_NO;
#endif
#ifdef HAVE_COMPRESS
  have_compress= SHOW_OPTION_YES;
#else
  have_compress= SHOW_OPTION_NO;
#endif
#ifdef HAVE_OPENSSL
  des_key_file = 0;
#ifndef EMBEDDED_LIBRARY
  ssl_acceptor_fd= 0;
#endif /* ! EMBEDDED_LIBRARY */
#endif /* HAVE_OPENSSL */
#if defined (_WIN32) && !defined (EMBEDDED_LIBRARY)
  shared_memory_base_name= default_shared_memory_base_name;
#endif

#if defined(_WIN32)
  /* Allow Win32 users to move MySQL anywhere */
  {
    char prg_dev[LIBLEN];
    char executing_path_name[LIBLEN];
    if (!test_if_hard_path(my_progname))
    {
      // we don't want to use GetModuleFileName inside of my_path since
      // my_path is a generic path dereferencing function and here we care
      // only about the executing binary.
      GetModuleFileName(NULL, executing_path_name, sizeof(executing_path_name));
      my_path(prg_dev, executing_path_name, NULL);
    }
    else
      my_path(prg_dev, my_progname, "mysql/bin");
    strcat(prg_dev,"/../");     // Remove 'bin' to get base dir
    cleanup_dirname(mysql_home,prg_dev);
  }
#else
  const char *tmpenv;
  if (!(tmpenv = getenv("MY_BASEDIR_VERSION")))
    tmpenv = DEFAULT_MYSQL_HOME;
  (void) strmake(mysql_home, tmpenv, sizeof(mysql_home)-1);
#endif
  return 0;
}

my_bool
mysqld_get_one_option(int optid,
                      const struct my_option *opt __attribute__((unused)),
                      char *argument)
{
  switch(optid) {
  case '#':
#ifndef DBUG_OFF
    DBUG_SET_INITIAL(argument ? argument : default_dbug_option);
#endif
    opt_endinfo=1;        /* unireg: memory allocation */
    break;
  case 'a':
    global_system_variables.sql_mode= MODE_ANSI;
    global_system_variables.tx_isolation= ISO_SERIALIZABLE;
    break;
  case 'b':
    strmake(mysql_home,argument,sizeof(mysql_home)-1);
    break;
  case 'C':
    if (default_collation_name == compiled_default_collation_name)
      default_collation_name= 0;
    break;
  case 'h':
    strmake(mysql_real_data_home,argument, sizeof(mysql_real_data_home)-1);
    /* Correct pointer set by my_getopt (for embedded library) */
    mysql_real_data_home_ptr= mysql_real_data_home;
    break;
  case 'u':
    if (!mysqld_user || !strcmp(mysqld_user, argument))
      mysqld_user= argument;
    else
      sql_print_warning("Ignoring user change to '%s' because the user was set to '%s' earlier on the command line\n", argument, mysqld_user);
    break;
  case 'L':
    push_deprecated_warn(NULL, "--language/-l", "'--lc-messages-dir'");
    /* Note:  fall-through */
  case OPT_LC_MESSAGES_DIRECTORY:
    strmake(lc_messages_dir, argument, sizeof(lc_messages_dir)-1);
    lc_messages_dir_ptr= lc_messages_dir;
    break;
  case OPT_BINLOG_FORMAT:
    binlog_format_used= true;
    break;
#include <sslopt-case.h>
#ifndef EMBEDDED_LIBRARY
  case 'V':
    print_version();
    exit(0);
#endif /*EMBEDDED_LIBRARY*/
  case 'W':
    push_deprecated_warn(NULL, "--log_warnings/-W", "'--log_error_verbosity'");
    if (!argument)
      log_error_verbosity++;
    else if (argument == disabled_my_option)
     log_error_verbosity= 1L;
    else
      log_error_verbosity= 1 + atoi(argument);
    log_error_verbosity= min(3UL, log_error_verbosity);
    break;
  case 'T':
    test_flags= argument ? (uint) atoi(argument) : 0;
    opt_endinfo=1;
    break;
  case (int) OPT_ISAM_LOG:
    opt_myisam_log=1;
    break;
  case (int) OPT_BIN_LOG:
    opt_bin_log= MY_TEST(argument != disabled_my_option);
    break;
#ifdef HAVE_REPLICATION
  case (int)OPT_REPLICATE_IGNORE_DB:
  {
    rpl_filter->add_ignore_db(argument);
    break;
  }
  case (int)OPT_REPLICATE_DO_DB:
  {
    rpl_filter->add_do_db(argument);
    break;
  }
  case (int)OPT_REPLICATE_REWRITE_DB:
  {
    char* key = argument,*p, *val;

    if (!(p= strstr(argument, "->")))
    {
      sql_print_error("Bad syntax in replicate-rewrite-db - missing '->'!\n");
      return 1;
    }
    val= p + 2;
    while(p > argument && my_isspace(mysqld_charset, p[-1]))
      p--;
    *p= 0;
    if (!*key)
    {
      sql_print_error("Bad syntax in replicate-rewrite-db - empty FROM db!\n");
      return 1;
    }
    while (*val && my_isspace(mysqld_charset, *val))
      val++;
    if (!*val)
    {
      sql_print_error("Bad syntax in replicate-rewrite-db - empty TO db!\n");
      return 1;
    }

    rpl_filter->add_db_rewrite(key, val);
    break;
  }

  case (int)OPT_BINLOG_IGNORE_DB:
  {
    binlog_filter->add_ignore_db(argument);
    break;
  }
  case (int)OPT_BINLOG_DO_DB:
  {
    binlog_filter->add_do_db(argument);
    break;
  }
  case (int)OPT_REPLICATE_DO_TABLE:
  {
    if (rpl_filter->add_do_table_array(argument))
    {
      sql_print_error("Could not add do table rule '%s'!\n", argument);
      return 1;
    }
    break;
  }
  case (int)OPT_REPLICATE_WILD_DO_TABLE:
  {
    if (rpl_filter->add_wild_do_table(argument))
    {
      sql_print_error("Could not add do table rule '%s'!\n", argument);
      return 1;
    }
    break;
  }
  case (int)OPT_REPLICATE_WILD_IGNORE_TABLE:
  {
    if (rpl_filter->add_wild_ignore_table(argument))
    {
      sql_print_error("Could not add ignore table rule '%s'!\n", argument);
      return 1;
    }
    break;
  }
  case (int)OPT_REPLICATE_IGNORE_TABLE:
  {
    if (rpl_filter->add_ignore_table_array(argument))
    {
      sql_print_error("Could not add ignore table rule '%s'!\n", argument);
      return 1;
    }
    break;
  }
#endif /* HAVE_REPLICATION */
  case (int) OPT_MASTER_RETRY_COUNT:
    push_deprecated_warn(NULL, "--master-retry-count", "'CHANGE MASTER TO master_retry_count = <num>'");
    break;
  case (int) OPT_SKIP_NEW:
    opt_specialflag|= SPECIAL_NO_NEW_FUNC;
    delay_key_write_options= DELAY_KEY_WRITE_NONE;
    myisam_concurrent_insert=0;
    myisam_recover_options= HA_RECOVER_OFF;
    sp_automatic_privileges=0;
    my_enable_symlinks= 0;
    ha_open_options&= ~(HA_OPEN_ABORT_IF_CRASHED | HA_OPEN_DELAY_KEY_WRITE);
    query_cache_size=0;
    break;
  case (int) OPT_SKIP_HOST_CACHE:
    opt_specialflag|= SPECIAL_NO_HOST_CACHE;
    break;
  case (int) OPT_SKIP_RESOLVE:
    opt_skip_name_resolve= 1;
    opt_specialflag|=SPECIAL_NO_RESOLVE;
    break;
  case (int) OPT_WANT_CORE:
    test_flags |= TEST_CORE_ON_SIGNAL;
    break;
  case (int) OPT_SKIP_STACK_TRACE:
    test_flags|=TEST_NO_STACKTRACE;
    break;
  case OPT_CONSOLE:
    if (opt_console)
      opt_error_log= 0;     // Force logs to stdout
    break;
  case OPT_BOOTSTRAP:
    opt_bootstrap=1;
    break;
  case OPT_SERVER_ID:
    /*
     Consider that one received a Server Id when 2 conditions are present:
     1) The argument is on the list
     2) There is a value present
    */
    server_id_supplied= (*argument != 0);

    break;
  case OPT_LOWER_CASE_TABLE_NAMES:
    lower_case_table_names_used= 1;
    break;
#if defined(ENABLED_DEBUG_SYNC)
  case OPT_DEBUG_SYNC_TIMEOUT:
    /*
      Debug Sync Facility. See debug_sync.cc.
      Default timeout for WAIT_FOR action.
      Default value is zero (facility disabled).
      If option is given without an argument, supply a non-zero value.
    */
    if (!argument)
    {
      /* purecov: begin tested */
      opt_debug_sync_timeout= DEBUG_SYNC_DEFAULT_WAIT_TIMEOUT;
      /* purecov: end */
    }
    break;
#endif /* defined(ENABLED_DEBUG_SYNC) */
  case OPT_LOG_ERROR:
    /*
      "No --log-error" == "write errors to stderr",
      "--log-error without argument" == "write errors to a file".
    */
    if (argument == NULL) /* no argument */
      log_error_file_ptr= const_cast<char*>("");
    break;

  case OPT_IGNORE_DB_DIRECTORY:
    if (*argument == 0)
      ignore_db_dirs_reset();
    else
    {
      if (push_ignored_db_dir(argument))
      {
        sql_print_error("Can't start server: "
                        "cannot process --ignore-db-dir=%.*s", 
                        FN_REFLEN, argument);
        return 1;
      }
    }
    break;


  case OPT_PLUGIN_LOAD:
    free_list(opt_plugin_load_list_ptr);
    /* fall through */
  case OPT_PLUGIN_LOAD_ADD:
    opt_plugin_load_list_ptr->push_back(new i_string(argument));
    break;
  case OPT_SECURE_AUTH:
    if (opt_secure_auth == 0)
      push_deprecated_warn(NULL, "pre-4.1 password hash", "post-4.1 password hash");
    break;
  case OPT_PFS_INSTRUMENT:
    {
#ifdef WITH_PERFSCHEMA_STORAGE_ENGINE
#ifndef EMBEDDED_LIBRARY

      /*
        Parse instrument name and value from argument string. Handle leading
        and trailing spaces. Also handle single quotes.

        Acceptable:
          performance_schema_instrument = ' foo/%/bar/  =  ON  '
          performance_schema_instrument = '%=OFF'
        Not acceptable:
          performance_schema_instrument = '' foo/%/bar = ON ''
          performance_schema_instrument = '%='OFF''
      */
      char *name= argument,*p= NULL, *val= NULL;
      my_bool quote= false; /* true if quote detected */
      my_bool error= true;  /* false if no errors detected */
      const int PFS_BUFFER_SIZE= 128;
      char orig_argument[PFS_BUFFER_SIZE+1];
      orig_argument[0]= 0;

      if (!argument)
        goto pfs_error;

      /* Save original argument string for error reporting */
      strncpy(orig_argument, argument, PFS_BUFFER_SIZE);

      /* Split instrument name and value at the equal sign */
      if (!(p= strchr(argument, '=')))
        goto pfs_error;

      /* Get option value */
      val= p + 1;
      if (!*val)
        goto pfs_error;

      /* Trim leading spaces and quote from the instrument name */
      while (*name && (my_isspace(mysqld_charset, *name) || (*name == '\'')))
      {
        /* One quote allowed */
        if (*name == '\'')
        {
          if (!quote)
            quote= true;
          else
            goto pfs_error;
        }
        name++;
      }

      /* Trim trailing spaces from instrument name */
      while ((p > name) && my_isspace(mysqld_charset, p[-1]))
        p--;
      *p= 0;

      /* Remove trailing slash from instrument name */
      if (p > name && (p[-1] == '/'))
        p[-1]= 0;

      if (!*name)
        goto pfs_error;

      /* Trim leading spaces from option value */
      while (*val && my_isspace(mysqld_charset, *val))
        val++;

      /* Trim trailing spaces and matching quote from value */
      p= val + strlen(val);
      while (p > val && (my_isspace(mysqld_charset, p[-1]) || p[-1] == '\''))
      {
        /* One matching quote allowed */
        if (p[-1] == '\'')
        {
          if (quote)
            quote= false;
          else
            goto pfs_error;
        }
        p--;
      }

      *p= 0;

      if (!*val)
        goto pfs_error;

      /* Add instrument name and value to array of configuration options */
      if (add_pfs_instr_to_array(name, val))
        goto pfs_error;

      error= false;

pfs_error:
      if (error)
      {
        my_getopt_error_reporter(WARNING_LEVEL,
                                 "Invalid instrument name or value for "
                                 "performance_schema_instrument '%s'",
                                 orig_argument);
        return 0;
      }
#endif /* EMBEDDED_LIBRARY */
#endif /* WITH_PERFSCHEMA_STORAGE_ENGINE */
      break;
    }
  case OPT_THREAD_CACHE_SIZE:
    thread_cache_size_specified= true;
    break;
  case OPT_HOST_CACHE_SIZE:
    host_cache_size_specified= true;
    break;
  case OPT_TABLE_DEFINITION_CACHE:
    table_definition_cache_specified= true;
    break;
  case OPT_MDL_CACHE_SIZE:
    push_deprecated_warn_no_replacement(NULL, "--metadata_locks_cache_size");
    break;
  case OPT_MDL_HASH_INSTANCES:
    push_deprecated_warn_no_replacement(NULL,
                                        "--metadata_locks_hash_instances");
    break;
  }
  return 0;
}


/** Handle arguments for multiple key caches. */

C_MODE_START

static void*
mysql_getopt_value(const char *keyname, size_t key_length,
       const struct my_option *option, int *error)
{
  if (error)
    *error= 0;
  switch (option->id) {
  case OPT_KEY_BUFFER_SIZE:
  case OPT_KEY_CACHE_BLOCK_SIZE:
  case OPT_KEY_CACHE_DIVISION_LIMIT:
  case OPT_KEY_CACHE_AGE_THRESHOLD:
  {
    KEY_CACHE *key_cache;
    if (!(key_cache= get_or_create_key_cache(keyname, key_length)))
    {
      if (error)
        *error= EXIT_OUT_OF_MEMORY;
      return 0;
    }
    switch (option->id) {
    case OPT_KEY_BUFFER_SIZE:
      return &key_cache->param_buff_size;
    case OPT_KEY_CACHE_BLOCK_SIZE:
      return &key_cache->param_block_size;
    case OPT_KEY_CACHE_DIVISION_LIMIT:
      return &key_cache->param_division_limit;
    case OPT_KEY_CACHE_AGE_THRESHOLD:
      return &key_cache->param_age_threshold;
    }
  }
  }
  return option->value;
}

static void option_error_reporter(enum loglevel level, const char *format, ...)
{
  va_list args;
  va_start(args, format);

  /* Don't print warnings for --loose options during bootstrap */
  if (level == ERROR_LEVEL || !opt_bootstrap ||
      (log_error_verbosity > 1))
  {
    error_log_print(level, format, args);
  }
  va_end(args);
}

C_MODE_END

/**
  Get server options from the command line,
  and perform related server initializations.
  @param [in, out] argc_ptr       command line options (count)
  @param [in, out] argv_ptr       command line options (values)
  @return 0 on success

  @todo
  - FIXME add EXIT_TOO_MANY_ARGUMENTS to "mysys_err.h" and return that code?
*/
static int get_options(int *argc_ptr, char ***argv_ptr)
{
  int ho_error;

  my_getopt_register_get_addr(mysql_getopt_value);
  my_getopt_error_reporter= option_error_reporter;

  /* prepare all_options array */
  all_options.reserve(array_elements(my_long_options));
  for (my_option *opt= my_long_options;
       opt < my_long_options + array_elements(my_long_options) - 1;
       opt++)
  {
    all_options.push_back(*opt);
  }
  sys_var_add_options(&all_options, sys_var::PARSE_NORMAL);
  add_terminator(&all_options);

  if (opt_help || opt_bootstrap)
  {
    /*
      Show errors during --help, but gag everything else so the info the
      user actually wants isn't lost in the spam.  (For --help --verbose,
      we need to set up far enough to be able to print variables provided
      by plugins, so a good number of warnings/notes might get printed.)
      Likewise for --bootstrap.
    */
    struct my_option *opt= &all_options[0];
    for (; opt->name; opt++)
      if (!strcmp("log_error_verbosity", opt->name))
        opt->def_value= 1;
  }

  /* Skip unknown options so that they may be processed later by plugins */
  my_getopt_skip_unknown= TRUE;

  if ((ho_error= handle_options(argc_ptr, argv_ptr, &all_options[0],
                                mysqld_get_one_option)))
    return ho_error;

  if (!opt_help)
    vector<my_option>().swap(all_options);  // Deletes the vector contents.

  /* Add back the program name handle_options removes */
  (*argc_ptr)++;
  (*argv_ptr)--;

  /*
    Options have been parsed. Now some of them need additional special
    handling, like custom value checking, checking of incompatibilites
    between options, setting of multiple variables, etc.
    Do them here.
  */

  if (!opt_help && opt_verbose)
    sql_print_error("--verbose is for use with --help; "
                    "did you mean --log-error-verbosity?");

  if ((opt_log_slow_admin_statements || opt_log_queries_not_using_indexes ||
       opt_log_slow_slave_statements) &&
      !opt_slow_log)
    sql_print_warning("options --log-slow-admin-statements, "
                      "--log-queries-not-using-indexes and "
                      "--log-slow-slave-statements have no effect if "
                      "--slow-query-log is not set");
  if (global_system_variables.net_buffer_length >
      global_system_variables.max_allowed_packet)
  {
    sql_print_warning("net_buffer_length (%lu) is set to be larger "
                      "than max_allowed_packet (%lu). Please rectify.",
                      global_system_variables.net_buffer_length,
                      global_system_variables.max_allowed_packet);
  }

  /*
    TIMESTAMP columns get implicit DEFAULT values when
    --explicit_defaults_for_timestamp is not set. 
    This behavior is deprecated now.
  */
  if (!opt_help && !global_system_variables.explicit_defaults_for_timestamp)
    sql_print_warning("TIMESTAMP with implicit DEFAULT value is deprecated. "
                      "Please use --explicit_defaults_for_timestamp server "
                      "option (see documentation for more details).");

  if (log_error_file_ptr != disabled_my_option)
#ifdef _WIN32
    /*
      Enable the error log only if console option is not specified 
      and MySQL is not running as a service.
    */
    opt_error_log= (opt_console && !start_mode ) ? false : true;
#else
    opt_error_log= true;
#endif
  else
    log_error_file_ptr= const_cast<char*>("");

  opt_init_connect.length=strlen(opt_init_connect.str);
  opt_init_slave.length=strlen(opt_init_slave.str);

  if (global_system_variables.low_priority_updates)
    thr_upgraded_concurrent_insert_lock= TL_WRITE_LOW_PRIORITY;

  if (ft_boolean_check_syntax_string((uchar*) ft_boolean_syntax))
  {
    sql_print_error("Invalid ft-boolean-syntax string: %s\n",
                    ft_boolean_syntax);
    return 1;
  }

  if (opt_disable_networking)
    mysqld_port= 0;

  if (opt_skip_show_db)
    opt_specialflag|= SPECIAL_SKIP_SHOW_DB;

  if (myisam_flush)
    flush_time= 0;

#ifdef HAVE_REPLICATION
  if (opt_slave_skip_errors)
    add_slave_skip_errors(opt_slave_skip_errors);
#endif

  if (global_system_variables.max_join_size == HA_POS_ERROR)
    global_system_variables.option_bits|= OPTION_BIG_SELECTS;
  else
    global_system_variables.option_bits&= ~OPTION_BIG_SELECTS;

  // Synchronize @@global.autocommit on --autocommit
  const ulonglong turn_bit_on= opt_autocommit ?
    OPTION_AUTOCOMMIT : OPTION_NOT_AUTOCOMMIT;
  global_system_variables.option_bits=
    (global_system_variables.option_bits &
     ~(OPTION_NOT_AUTOCOMMIT | OPTION_AUTOCOMMIT)) | turn_bit_on;

  global_system_variables.sql_mode=
    expand_sql_mode(global_system_variables.sql_mode);

  if (!my_enable_symlinks)
    have_symlink= SHOW_OPTION_DISABLED;

  if (opt_debugging)
  {
    /* Allow break with SIGINT, no core or stack trace */
    test_flags|= TEST_SIGINT | TEST_NO_STACKTRACE;
    test_flags&= ~TEST_CORE_ON_SIGNAL;
  }
  /* Set global MyISAM variables from delay_key_write_options */
  fix_delay_key_write(0, 0, OPT_GLOBAL);

#ifndef EMBEDDED_LIBRARY
#ifndef _WIN32
  if (mysqld_chroot)
    set_root(mysqld_chroot);
#endif
#else
  max_allowed_packet= global_system_variables.max_allowed_packet;
  net_buffer_length= global_system_variables.net_buffer_length;
#endif
  if (fix_paths())
    return 1;

  /*
    Set some global variables from the global_system_variables
    In most cases the global variables will not be used
  */
  my_disable_locking= myisam_single_user= MY_TEST(opt_external_locking == 0);
  my_default_record_cache_size=global_system_variables.read_buff_size;

  global_system_variables.long_query_time= (ulonglong)
    (global_system_variables.long_query_time_double * 1e6);

  if (opt_short_log_format)
    opt_specialflag|= SPECIAL_SHORT_LOG_FORMAT;

  if (init_global_datetime_format(MYSQL_TIMESTAMP_DATE,
                                  &global_date_format) ||
      init_global_datetime_format(MYSQL_TIMESTAMP_TIME,
                                  &global_time_format) ||
      init_global_datetime_format(MYSQL_TIMESTAMP_DATETIME,
                                  &global_datetime_format))
    return 1;

#ifndef EMBEDDED_LIBRARY
  if (Connection_handler_manager::init())
  {
    sql_print_error("Could not allocate memory for connection handling");
    return 1;
  }
#endif
  if (Global_THD_manager::create_instance())
  {
    sql_print_error("Could not allocate memory for thread handling");
    return 1;
  }

  opt_readonly= read_only;

  return 0;
}


/*
  Create version name for running mysqld version
  We automaticly add suffixes -debug, -embedded, -log, -valgrind and -asan
  to the version name to make the version more descriptive.
  (MYSQL_SERVER_SUFFIX is set by the compilation environment)
*/

static void set_server_version(void)
{
  char *end= strxmov(server_version, MYSQL_SERVER_VERSION,
                     MYSQL_SERVER_SUFFIX_STR, NullS);
#ifdef EMBEDDED_LIBRARY
  end= my_stpcpy(end, "-embedded");
#endif
#ifndef DBUG_OFF
  if (!strstr(MYSQL_SERVER_SUFFIX_STR, "-debug"))
    end= my_stpcpy(end, "-debug");
#endif
  if (opt_general_log || opt_slow_log || opt_bin_log)
    end= my_stpcpy(end, "-log");          // This may slow down system
#ifdef HAVE_VALGRIND
  if (SERVER_VERSION_LENGTH - (end - server_version) >
      static_cast<int>(sizeof("-valgrind")))
    end= my_stpcpy(end, "-valgrind"); 
#endif
#ifdef HAVE_ASAN
  if (SERVER_VERSION_LENGTH - (end - server_version) >
      static_cast<int>(sizeof("-asan")))
    end= my_stpcpy(end, "-asan");
#endif
}


static char *get_relative_path(const char *path)
{
  if (test_if_hard_path(path) &&
      is_prefix(path,DEFAULT_MYSQL_HOME) &&
      strcmp(DEFAULT_MYSQL_HOME,FN_ROOTDIR))
  {
    path+=(uint) strlen(DEFAULT_MYSQL_HOME);
    while (*path == FN_LIBCHAR || *path == FN_LIBCHAR2)
      path++;
  }
  return (char*) path;
}


/**
  Fix filename and replace extension where 'dir' is relative to
  mysql_real_data_home.
  @return
    1 if len(path) > FN_REFLEN
*/

bool
fn_format_relative_to_data_home(char * to, const char *name,
        const char *dir, const char *extension)
{
  char tmp_path[FN_REFLEN];
  if (!test_if_hard_path(dir))
  {
    strxnmov(tmp_path,sizeof(tmp_path)-1, mysql_real_data_home,
       dir, NullS);
    dir=tmp_path;
  }
  return !fn_format(to, name, dir, extension,
        MY_APPEND_EXT | MY_UNPACK_FILENAME | MY_SAFE_PATH);
}


/**
  Test a file path to determine if the path is compatible with the secure file
  path restriction.

  @param path null terminated character string

  @return
    @retval TRUE The path is secure
    @retval FALSE The path isn't secure
*/

bool is_secure_file_path(char *path)
{
  char buff1[FN_REFLEN], buff2[FN_REFLEN];
  size_t opt_secure_file_priv_len;
  /*
    All paths are secure if opt_secure_file_path is 0
  */
  if (!opt_secure_file_priv)
    return TRUE;

  opt_secure_file_priv_len= strlen(opt_secure_file_priv);

  if (strlen(path) >= FN_REFLEN)
    return FALSE;

  if (my_realpath(buff1, path, 0))
  {
    /*
      The supplied file path might have been a file and not a directory.
    */
    int length= (int)dirname_length(path);
    if (length >= FN_REFLEN)
      return FALSE;
    memcpy(buff2, path, length);
    buff2[length]= '\0';
    if (length == 0 || my_realpath(buff1, buff2, 0))
      return FALSE;
  }
  convert_dirname(buff2, buff1, NullS);
  if (!lower_case_file_system)
  {
    if (strncmp(opt_secure_file_priv, buff2, opt_secure_file_priv_len))
      return FALSE;
  }
  else
  {
    if (files_charset_info->coll->strnncoll(files_charset_info,
                                            (uchar *) buff2, strlen(buff2),
                                            (uchar *) opt_secure_file_priv,
                                            opt_secure_file_priv_len,
                                            TRUE))
      return FALSE;
  }
  return TRUE;
}


static int fix_paths(void)
{
  char buff[FN_REFLEN],*pos;
  convert_dirname(mysql_home,mysql_home,NullS);
  /* Resolve symlinks to allow 'mysql_home' to be a relative symlink */
  my_realpath(mysql_home,mysql_home,MYF(0));
  /* Ensure that mysql_home ends in FN_LIBCHAR */
  pos=strend(mysql_home);
  if (pos[-1] != FN_LIBCHAR)
  {
    pos[0]= FN_LIBCHAR;
    pos[1]= 0;
  }
  convert_dirname(lc_messages_dir, lc_messages_dir, NullS);
  convert_dirname(mysql_real_data_home,mysql_real_data_home,NullS);
  (void) my_load_path(mysql_home,mysql_home,""); // Resolve current dir
  (void) my_load_path(mysql_real_data_home,mysql_real_data_home,mysql_home);
  (void) my_load_path(pidfile_name, pidfile_name_ptr, mysql_real_data_home);

  convert_dirname(opt_plugin_dir, opt_plugin_dir_ptr ? opt_plugin_dir_ptr : 
                                  get_relative_path(PLUGINDIR), NullS);
  (void) my_load_path(opt_plugin_dir, opt_plugin_dir, mysql_home);
  opt_plugin_dir_ptr= opt_plugin_dir;

  my_realpath(mysql_unpacked_real_data_home, mysql_real_data_home, MYF(0));
  mysql_unpacked_real_data_home_len=
    strlen(mysql_unpacked_real_data_home);
  if (mysql_unpacked_real_data_home[mysql_unpacked_real_data_home_len-1] == FN_LIBCHAR)
    --mysql_unpacked_real_data_home_len;

  char *sharedir=get_relative_path(SHAREDIR);
  if (test_if_hard_path(sharedir))
    strmake(buff,sharedir,sizeof(buff)-1);    /* purecov: tested */
  else
    strxnmov(buff,sizeof(buff)-1,mysql_home,sharedir,NullS);
  convert_dirname(buff,buff,NullS);
  (void) my_load_path(lc_messages_dir, lc_messages_dir, buff);

  /* If --character-sets-dir isn't given, use shared library dir */
  if (charsets_dir)
    strmake(mysql_charsets_dir, charsets_dir, sizeof(mysql_charsets_dir)-1);
  else
    strxnmov(mysql_charsets_dir, sizeof(mysql_charsets_dir)-1, buff,
       CHARSET_DIR, NullS);
  (void) my_load_path(mysql_charsets_dir, mysql_charsets_dir, buff);
  convert_dirname(mysql_charsets_dir, mysql_charsets_dir, NullS);
  charsets_dir=mysql_charsets_dir;

  if (init_tmpdir(&mysql_tmpdir_list, opt_mysql_tmpdir))
    return 1;
  if (!opt_mysql_tmpdir)
    opt_mysql_tmpdir= mysql_tmpdir;
#ifdef HAVE_REPLICATION
  if (!slave_load_tmpdir)
    slave_load_tmpdir= mysql_tmpdir;
#endif /* HAVE_REPLICATION */
  /*
    Convert the secure-file-priv option to system format, allowing
    a quick strcmp to check if read or write is in an allowed dir
   */
  if (opt_secure_file_priv)
  {
    if (*opt_secure_file_priv == 0)
      opt_secure_file_priv= NULL;
    else
    {
      if (strlen(opt_secure_file_priv) >= FN_REFLEN)
        opt_secure_file_priv[FN_REFLEN-1]= '\0';
      if (my_realpath(buff, opt_secure_file_priv, 0))
      {
        sql_print_warning("Failed to normalize the argument for --secure-file-priv.");
        return 1;
      }
      convert_dirname(secure_file_real_path, buff, NullS);
      opt_secure_file_priv= secure_file_real_path;
    }
  }

  return 0;
}

/**
  Check if file system used for databases is case insensitive.

  @param dir_name     Directory to test

  @retval
    -1  Don't know (Test failed)
  @retval
    0   File system is case sensitive
  @retval
    1   File system is case insensitive
*/

static int test_if_case_insensitive(const char *dir_name)
{
  int result= 0;
  File file;
  char buff[FN_REFLEN], buff2[FN_REFLEN];
  MY_STAT stat_info;
  DBUG_ENTER("test_if_case_insensitive");

  fn_format(buff, glob_hostname, dir_name, ".lower-test",
      MY_UNPACK_FILENAME | MY_REPLACE_EXT | MY_REPLACE_DIR);
  fn_format(buff2, glob_hostname, dir_name, ".LOWER-TEST",
      MY_UNPACK_FILENAME | MY_REPLACE_EXT | MY_REPLACE_DIR);
  mysql_file_delete(key_file_casetest, buff2, MYF(0));
  if ((file= mysql_file_create(key_file_casetest,
                               buff, 0666, O_RDWR, MYF(0))) < 0)
  {
    sql_print_warning("Can't create test file %s", buff);
    DBUG_RETURN(-1);
  }
  mysql_file_close(file, MYF(0));
  if (mysql_file_stat(key_file_casetest, buff2, &stat_info, MYF(0)))
    result= 1;          // Can access file
  mysql_file_delete(key_file_casetest, buff, MYF(MY_WME));
  DBUG_PRINT("exit", ("result: %d", result));
  DBUG_RETURN(result);
}


#ifndef EMBEDDED_LIBRARY

/**
  Create file to store pid number.
*/
static void create_pid_file()
{
  File file;
  if ((file= mysql_file_create(key_file_pid, pidfile_name, 0664,
                               O_WRONLY | O_TRUNC, MYF(MY_WME))) >= 0)
  {
    char buff[MAX_BIGINT_WIDTH + 1], *end;
    end= int10_to_str((long) getpid(), buff, 10);
    *end++= '\n';
    if (!mysql_file_write(file, (uchar*) buff, (uint) (end-buff),
                          MYF(MY_WME | MY_NABP)))
    {
      mysql_file_close(file, MYF(0));
      pid_file_created= true;
      return;
    }
    mysql_file_close(file, MYF(0));
  }
  sql_print_error("Can't start server: can't create PID file: %s",
                  strerror(errno));
  exit(1);
}


/**
  Remove the process' pid file.

  @param  flags  file operation flags
*/

static void delete_pid_file(myf flags)
{
  File file;
  if (opt_bootstrap ||
      !pid_file_created ||
      !(file= mysql_file_open(key_file_pid, pidfile_name,
                              O_RDONLY, flags)))
    return;

  /* Make sure that the pid file was created by the same process. */    
  uchar buff[MAX_BIGINT_WIDTH + 1];
  size_t error= mysql_file_read(file, buff, sizeof(buff), flags);
  mysql_file_close(file, flags);
  buff[sizeof(buff) - 1]= '\0'; 
  if (error != MY_FILE_ERROR &&
      atol((char *) buff) == (long) getpid())
  {
    mysql_file_delete(key_file_pid, pidfile_name, flags);
    pid_file_created= false;
  }
  return;
}
#endif /* EMBEDDED_LIBRARY */


/** Clear most status variables. */
void refresh_status(THD *thd)
{
  mysql_mutex_lock(&LOCK_status);

  /* Add thread's status variabes to global status */
  add_to_status(&global_status_var, &thd->status_var);

  /* Reset thread's status variables */
  memset(&thd->status_var, 0, sizeof(thd->status_var));

  /* Reset some global variables */
  reset_status_vars();

  /* Reset the counters of all key caches (default and named). */
  process_key_caches(reset_key_cache_counters);
  flush_status_time= time((time_t*) 0);
  mysql_mutex_unlock(&LOCK_status);

#ifndef EMBEDDED_LIBRARY
  /*
    Set max_used_connections to the number of currently open
    connections.  Do this out of LOCK_status to avoid deadlocks.
    Status reset becomes not atomic, but status data is not exact anyway.
  */
  Connection_handler_manager::reset_max_used_connections();
#endif
}


/*****************************************************************************
  Instantiate variables for missing storage engines
  This section should go away soon
*****************************************************************************/

#ifdef HAVE_PSI_INTERFACE
#ifdef HAVE_MMAP
PSI_mutex_key key_LOCK_tc;
#endif /* HAVE_MMAP */

#ifdef HAVE_OPENSSL
PSI_mutex_key key_LOCK_des_key_file;
#endif /* HAVE_OPENSSL */

PSI_mutex_key key_BINLOG_LOCK_commit;
PSI_mutex_key key_BINLOG_LOCK_commit_queue;
PSI_mutex_key key_BINLOG_LOCK_done;
PSI_mutex_key key_BINLOG_LOCK_flush_queue;
PSI_mutex_key key_BINLOG_LOCK_index;
PSI_mutex_key key_BINLOG_LOCK_log;
PSI_mutex_key key_BINLOG_LOCK_binlog_end_pos;
PSI_mutex_key key_BINLOG_LOCK_sync;
PSI_mutex_key key_BINLOG_LOCK_sync_queue;
PSI_mutex_key key_BINLOG_LOCK_xids;
PSI_mutex_key
  key_hash_filo_lock, key_LOCK_active_mi,
  key_LOCK_crypt, key_LOCK_error_log,
  key_LOCK_gdl, key_LOCK_global_system_variables,
  key_LOCK_manager,
  key_LOCK_prepared_stmt_count,
  key_LOCK_server_started, key_LOCK_status,
  key_LOCK_sql_slave_skip_counter,
  key_LOCK_slave_net_timeout,
  key_LOCK_system_variables_hash, key_LOCK_table_share, key_LOCK_thd_data,
  key_LOCK_user_conn, key_LOCK_uuid_generator, key_LOG_LOCK_log,
  key_master_info_data_lock, key_master_info_run_lock,
  key_master_info_sleep_lock, key_master_info_thd_lock,
  key_mutex_slave_reporting_capability_err_lock, key_relay_log_info_data_lock,
  key_relay_log_info_sleep_lock, key_relay_log_info_thd_lock,
  key_relay_log_info_log_space_lock, key_relay_log_info_run_lock,
  key_mutex_slave_parallel_pend_jobs, key_mutex_mts_temp_tables_lock,
  key_mutex_slave_parallel_worker,
  key_structure_guard_mutex, key_TABLE_SHARE_LOCK_ha_data,
  key_LOCK_error_messages,
  key_LOCK_log_throttle_qni, key_LOCK_query_plan, key_LOCK_thd_query;
PSI_mutex_key key_RELAYLOG_LOCK_commit;
PSI_mutex_key key_RELAYLOG_LOCK_commit_queue;
PSI_mutex_key key_RELAYLOG_LOCK_done;
PSI_mutex_key key_RELAYLOG_LOCK_flush_queue;
PSI_mutex_key key_RELAYLOG_LOCK_index;
PSI_mutex_key key_RELAYLOG_LOCK_log;
PSI_mutex_key key_RELAYLOG_LOCK_sync;
PSI_mutex_key key_RELAYLOG_LOCK_sync_queue;
PSI_mutex_key key_RELAYLOG_LOCK_xids;
PSI_mutex_key key_LOCK_sql_rand;
PSI_mutex_key key_gtid_ensure_index_mutex;
PSI_mutex_key key_mts_temp_table_LOCK;
#ifdef HAVE_MY_TIMER
PSI_mutex_key key_thd_timer_mutex;
#endif

static PSI_mutex_info all_server_mutexes[]=
{
#ifdef HAVE_MMAP
  { &key_LOCK_tc, "TC_LOG_MMAP::LOCK_tc", 0},
#endif /* HAVE_MMAP */

#ifdef HAVE_OPENSSL
  { &key_LOCK_des_key_file, "LOCK_des_key_file", PSI_FLAG_GLOBAL},
#endif /* HAVE_OPENSSL */

  { &key_BINLOG_LOCK_commit, "MYSQL_BIN_LOG::LOCK_commit", 0 },
  { &key_BINLOG_LOCK_commit_queue, "MYSQL_BIN_LOG::LOCK_commit_queue", 0 },
  { &key_BINLOG_LOCK_done, "MYSQL_BIN_LOG::LOCK_done", 0 },
  { &key_BINLOG_LOCK_flush_queue, "MYSQL_BIN_LOG::LOCK_flush_queue", 0 },
  { &key_BINLOG_LOCK_index, "MYSQL_BIN_LOG::LOCK_index", 0},
  { &key_BINLOG_LOCK_log, "MYSQL_BIN_LOG::LOCK_log", 0},
  { &key_BINLOG_LOCK_binlog_end_pos, "MYSQL_BIN_LOG::LOCK_binlog_end_pos", 0},
  { &key_BINLOG_LOCK_sync, "MYSQL_BIN_LOG::LOCK_sync", 0},
  { &key_BINLOG_LOCK_sync_queue, "MYSQL_BIN_LOG::LOCK_sync_queue", 0 },
  { &key_BINLOG_LOCK_xids, "MYSQL_BIN_LOG::LOCK_xids", 0 },
  { &key_RELAYLOG_LOCK_commit, "MYSQL_RELAY_LOG::LOCK_commit", 0},
  { &key_RELAYLOG_LOCK_commit_queue, "MYSQL_RELAY_LOG::LOCK_commit_queue", 0 },
  { &key_RELAYLOG_LOCK_done, "MYSQL_RELAY_LOG::LOCK_done", 0 },
  { &key_RELAYLOG_LOCK_flush_queue, "MYSQL_RELAY_LOG::LOCK_flush_queue", 0 },
  { &key_RELAYLOG_LOCK_index, "MYSQL_RELAY_LOG::LOCK_index", 0},
  { &key_RELAYLOG_LOCK_log, "MYSQL_RELAY_LOG::LOCK_log", 0},
  { &key_RELAYLOG_LOCK_sync, "MYSQL_RELAY_LOG::LOCK_sync", 0},
  { &key_RELAYLOG_LOCK_sync_queue, "MYSQL_RELAY_LOG::LOCK_sync_queue", 0 },
  { &key_RELAYLOG_LOCK_xids, "MYSQL_RELAY_LOG::LOCK_xids", 0},
  { &key_hash_filo_lock, "hash_filo::lock", 0},
  { &key_LOCK_active_mi, "LOCK_active_mi", PSI_FLAG_GLOBAL},
  { &key_LOCK_crypt, "LOCK_crypt", PSI_FLAG_GLOBAL},
  { &key_LOCK_error_log, "LOCK_error_log", PSI_FLAG_GLOBAL},
  { &key_LOCK_gdl, "LOCK_gdl", PSI_FLAG_GLOBAL},
  { &key_LOCK_global_system_variables, "LOCK_global_system_variables", PSI_FLAG_GLOBAL},
#if defined(_WIN32) && !defined(EMBEDDED_LIBRARY)
  { &key_LOCK_handler_count, "LOCK_handler_count", PSI_FLAG_GLOBAL},
#endif
  { &key_LOCK_manager, "LOCK_manager", PSI_FLAG_GLOBAL},
  { &key_LOCK_prepared_stmt_count, "LOCK_prepared_stmt_count", PSI_FLAG_GLOBAL},
  { &key_LOCK_sql_slave_skip_counter, "LOCK_sql_slave_skip_counter", PSI_FLAG_GLOBAL},
  { &key_LOCK_slave_net_timeout, "LOCK_slave_net_timeout", PSI_FLAG_GLOBAL},
  { &key_LOCK_server_started, "LOCK_server_started", PSI_FLAG_GLOBAL},
#if !defined(EMBEDDED_LIBRARY) && !defined(_WIN32)
  { &key_LOCK_socket_listener_active, "LOCK_socket_listener_active", PSI_FLAG_GLOBAL},
  { &key_LOCK_start_signal_handler, "LOCK_start_signal_handler", PSI_FLAG_GLOBAL},
#endif
  { &key_LOCK_status, "LOCK_status", PSI_FLAG_GLOBAL},
  { &key_LOCK_system_variables_hash, "LOCK_system_variables_hash", PSI_FLAG_GLOBAL},
  { &key_LOCK_table_share, "LOCK_table_share", PSI_FLAG_GLOBAL},
  { &key_LOCK_thd_data, "THD::LOCK_thd_data", 0},
  { &key_LOCK_thd_query, "THD::LOCK_thd_query", 0},
  { &key_LOCK_user_conn, "LOCK_user_conn", PSI_FLAG_GLOBAL},
  { &key_LOCK_uuid_generator, "LOCK_uuid_generator", PSI_FLAG_GLOBAL},
  { &key_LOCK_sql_rand, "LOCK_sql_rand", PSI_FLAG_GLOBAL},
  { &key_LOG_LOCK_log, "LOG::LOCK_log", 0},
  { &key_master_info_data_lock, "Master_info::data_lock", 0},
  { &key_master_info_run_lock, "Master_info::run_lock", 0},
  { &key_master_info_sleep_lock, "Master_info::sleep_lock", 0},
  { &key_master_info_thd_lock, "Master_info::info_thd_lock", 0},
  { &key_mutex_slave_reporting_capability_err_lock, "Slave_reporting_capability::err_lock", 0},
  { &key_relay_log_info_data_lock, "Relay_log_info::data_lock", 0},
  { &key_relay_log_info_sleep_lock, "Relay_log_info::sleep_lock", 0},
  { &key_relay_log_info_thd_lock, "Relay_log_info::info_thd_lock", 0},
  { &key_relay_log_info_log_space_lock, "Relay_log_info::log_space_lock", 0},
  { &key_relay_log_info_run_lock, "Relay_log_info::run_lock", 0},
  { &key_mutex_slave_parallel_pend_jobs, "Relay_log_info::pending_jobs_lock", 0},
  { &key_mutex_mts_temp_tables_lock, "Relay_log_info::temp_tables_lock", 0},
  { &key_mutex_slave_parallel_worker, "Worker_info::jobs_lock", 0},
  { &key_structure_guard_mutex, "Query_cache::structure_guard_mutex", 0},
  { &key_TABLE_SHARE_LOCK_ha_data, "TABLE_SHARE::LOCK_ha_data", 0},
  { &key_LOCK_error_messages, "LOCK_error_messages", PSI_FLAG_GLOBAL},
  { &key_LOCK_log_throttle_qni, "LOCK_log_throttle_qni", PSI_FLAG_GLOBAL},
  { &key_gtid_ensure_index_mutex, "Gtid_state", PSI_FLAG_GLOBAL},
  { &key_LOCK_query_plan, "THD::LOCK_query_plan", 0},
  { &key_mts_temp_table_LOCK, "key_mts_temp_table_LOCK",0},
#ifdef HAVE_MY_TIMER
  { &key_thd_timer_mutex, "thd_timer_mutex", 0},
#endif
};

PSI_rwlock_key key_rwlock_LOCK_grant, key_rwlock_LOCK_logger,
  key_rwlock_LOCK_sys_init_connect, key_rwlock_LOCK_sys_init_slave,
  key_rwlock_LOCK_system_variables_hash, key_rwlock_query_cache_query_lock,
  key_rwlock_global_sid_lock;

PSI_rwlock_key key_rwlock_Trans_delegate_lock;
PSI_rwlock_key key_rwlock_Binlog_storage_delegate_lock;
#ifdef HAVE_REPLICATION
PSI_rwlock_key key_rwlock_Binlog_transmit_delegate_lock;
PSI_rwlock_key key_rwlock_Binlog_relay_IO_delegate_lock;
#endif

static PSI_rwlock_info all_server_rwlocks[]=
{
#if defined (HAVE_OPENSSL) && !defined(HAVE_YASSL)
  { &key_rwlock_openssl, "CRYPTO_dynlock_value::lock", 0},
#endif
#ifdef HAVE_REPLICATION
  { &key_rwlock_Binlog_transmit_delegate_lock, "Binlog_transmit_delegate::lock", PSI_FLAG_GLOBAL},
  { &key_rwlock_Binlog_relay_IO_delegate_lock, "Binlog_relay_IO_delegate::lock", PSI_FLAG_GLOBAL},
#endif
  { &key_rwlock_LOCK_grant, "LOCK_grant", PSI_FLAG_GLOBAL},
  { &key_rwlock_LOCK_logger, "LOGGER::LOCK_logger", 0},
  { &key_rwlock_LOCK_sys_init_connect, "LOCK_sys_init_connect", PSI_FLAG_GLOBAL},
  { &key_rwlock_LOCK_sys_init_slave, "LOCK_sys_init_slave", PSI_FLAG_GLOBAL},
  { &key_rwlock_LOCK_system_variables_hash, "LOCK_system_variables_hash", PSI_FLAG_GLOBAL},
  { &key_rwlock_query_cache_query_lock, "Query_cache_query::lock", 0},
  { &key_rwlock_global_sid_lock, "gtid_commit_rollback", PSI_FLAG_GLOBAL},
  { &key_rwlock_Trans_delegate_lock, "Trans_delegate::lock", PSI_FLAG_GLOBAL},
  { &key_rwlock_Binlog_storage_delegate_lock, "Binlog_storage_delegate::lock", PSI_FLAG_GLOBAL}
};

#ifdef HAVE_MMAP
PSI_cond_key key_PAGE_cond, key_COND_active, key_COND_pool;
#endif /* HAVE_MMAP */

PSI_cond_key key_BINLOG_update_cond,
  key_COND_cache_status_changed, key_COND_manager,
  key_COND_server_started,
  key_item_func_sleep_cond, key_master_info_data_cond,
  key_master_info_start_cond, key_master_info_stop_cond,
  key_master_info_sleep_cond,
  key_relay_log_info_data_cond, key_relay_log_info_log_space_cond,
  key_relay_log_info_start_cond, key_relay_log_info_stop_cond,
  key_relay_log_info_sleep_cond, key_cond_slave_parallel_pend_jobs,
  key_cond_slave_parallel_worker,
  key_TABLE_SHARE_cond, key_user_level_lock_cond;
PSI_cond_key key_RELAYLOG_update_cond;
PSI_cond_key key_BINLOG_COND_done;
PSI_cond_key key_RELAYLOG_COND_done;
PSI_cond_key key_BINLOG_prep_xids_cond;
PSI_cond_key key_RELAYLOG_prep_xids_cond;
PSI_cond_key key_gtid_ensure_index_cond;

static PSI_cond_info all_server_conds[]=
{
#ifdef HAVE_MMAP
  { &key_PAGE_cond, "PAGE::cond", 0},
  { &key_COND_active, "TC_LOG_MMAP::COND_active", 0},
  { &key_COND_pool, "TC_LOG_MMAP::COND_pool", 0},
#endif /* HAVE_MMAP */
  { &key_BINLOG_COND_done, "MYSQL_BIN_LOG::COND_done", 0},
  { &key_BINLOG_update_cond, "MYSQL_BIN_LOG::update_cond", 0},
  { &key_BINLOG_prep_xids_cond, "MYSQL_BIN_LOG::prep_xids_cond", 0},
  { &key_RELAYLOG_COND_done, "MYSQL_RELAY_LOG::COND_done", 0},
  { &key_RELAYLOG_update_cond, "MYSQL_RELAY_LOG::update_cond", 0},
  { &key_RELAYLOG_prep_xids_cond, "MYSQL_RELAY_LOG::prep_xids_cond", 0},
  { &key_COND_cache_status_changed, "Query_cache::COND_cache_status_changed", 0},
#if defined(_WIN32) && !defined(EMBEDDED_LIBRARY)
  { &key_COND_handler_count, "COND_handler_count", PSI_FLAG_GLOBAL},
#endif
  { &key_COND_manager, "COND_manager", PSI_FLAG_GLOBAL},
  { &key_COND_server_started, "COND_server_started", PSI_FLAG_GLOBAL},
#if !defined(EMBEDDED_LIBRARY) && !defined(_WIN32)
  { &key_COND_socket_listener_active, "COND_socket_listener_active", PSI_FLAG_GLOBAL},
  { &key_COND_start_signal_handler, "COND_start_signal_handler", PSI_FLAG_GLOBAL},
#endif
  { &key_item_func_sleep_cond, "Item_func_sleep::cond", 0},
  { &key_master_info_data_cond, "Master_info::data_cond", 0},
  { &key_master_info_start_cond, "Master_info::start_cond", 0},
  { &key_master_info_stop_cond, "Master_info::stop_cond", 0},
  { &key_master_info_sleep_cond, "Master_info::sleep_cond", 0},
  { &key_relay_log_info_data_cond, "Relay_log_info::data_cond", 0},
  { &key_relay_log_info_log_space_cond, "Relay_log_info::log_space_cond", 0},
  { &key_relay_log_info_start_cond, "Relay_log_info::start_cond", 0},
  { &key_relay_log_info_stop_cond, "Relay_log_info::stop_cond", 0},
  { &key_relay_log_info_sleep_cond, "Relay_log_info::sleep_cond", 0},
  { &key_cond_slave_parallel_pend_jobs, "Relay_log_info::pending_jobs_cond", 0},
  { &key_cond_slave_parallel_worker, "Worker_info::jobs_cond", 0},
  { &key_TABLE_SHARE_cond, "TABLE_SHARE::cond", 0},
  { &key_user_level_lock_cond, "User_level_lock::cond", 0},
  { &key_gtid_ensure_index_cond, "Gtid_state", PSI_FLAG_GLOBAL}
};

PSI_thread_key key_thread_bootstrap, key_thread_handle_manager, key_thread_main,
  key_thread_one_connection, key_thread_signal_hand;

#ifdef HAVE_MY_TIMER
PSI_thread_key key_thread_timer_notifier;
#endif

static PSI_thread_info all_server_threads[]=
{
#if defined (_WIN32) && !defined (EMBEDDED_LIBRARY)
  { &key_thread_handle_con_namedpipes, "con_named_pipes", PSI_FLAG_GLOBAL},
  { &key_thread_handle_con_sharedmem, "con_shared_mem", PSI_FLAG_GLOBAL},
  { &key_thread_handle_con_sockets, "con_sockets", PSI_FLAG_GLOBAL},
  { &key_thread_handle_shutdown, "shutdown", PSI_FLAG_GLOBAL},
#endif /* _WIN32 && !EMBEDDED_LIBRARY */
#ifdef HAVE_MY_TIMER
  { &key_thread_timer_notifier, "thread_timer_notifier", PSI_FLAG_GLOBAL},
#endif
  { &key_thread_bootstrap, "bootstrap", PSI_FLAG_GLOBAL},
  { &key_thread_handle_manager, "manager", PSI_FLAG_GLOBAL},
  { &key_thread_main, "main", PSI_FLAG_GLOBAL},
  { &key_thread_one_connection, "one_connection", 0},
  { &key_thread_signal_hand, "signal_handler", PSI_FLAG_GLOBAL}
};

#ifdef HAVE_MMAP
PSI_file_key key_file_map;
#endif /* HAVE_MMAP */

PSI_file_key key_file_binlog, key_file_binlog_index, key_file_casetest,
  key_file_dbopt, key_file_des_key_file, key_file_ERRMSG, key_select_to_file,
  key_file_fileparser, key_file_frm, key_file_global_ddl_log, key_file_load,
  key_file_loadfile, key_file_log_event_data, key_file_log_event_info,
  key_file_master_info, key_file_misc, key_file_partition,
  key_file_pid, key_file_relay_log_info, key_file_send_file, key_file_tclog,
  key_file_trg, key_file_trn, key_file_init;
PSI_file_key key_file_general_log, key_file_slow_log;
PSI_file_key key_file_relaylog, key_file_relaylog_index;

static PSI_file_info all_server_files[]=
{
#ifdef HAVE_MMAP
  { &key_file_map, "map", 0},
#endif /* HAVE_MMAP */
  { &key_file_binlog, "binlog", 0},
  { &key_file_binlog_index, "binlog_index", 0},
  { &key_file_relaylog, "relaylog", 0},
  { &key_file_relaylog_index, "relaylog_index", 0},
  { &key_file_casetest, "casetest", 0},
  { &key_file_dbopt, "dbopt", 0},
  { &key_file_des_key_file, "des_key_file", 0},
  { &key_file_ERRMSG, "ERRMSG", 0},
  { &key_select_to_file, "select_to_file", 0},
  { &key_file_fileparser, "file_parser", 0},
  { &key_file_frm, "FRM", 0},
  { &key_file_global_ddl_log, "global_ddl_log", 0},
  { &key_file_load, "load", 0},
  { &key_file_loadfile, "LOAD_FILE", 0},
  { &key_file_log_event_data, "log_event_data", 0},
  { &key_file_log_event_info, "log_event_info", 0},
  { &key_file_master_info, "master_info", 0},
  { &key_file_misc, "misc", 0},
  { &key_file_partition, "partition", 0},
  { &key_file_pid, "pid", 0},
  { &key_file_general_log, "query_log", 0},
  { &key_file_relay_log_info, "relay_log_info", 0},
  { &key_file_send_file, "send_file", 0},
  { &key_file_slow_log, "slow_log", 0},
  { &key_file_tclog, "tclog", 0},
  { &key_file_trg, "trigger_name", 0},
  { &key_file_trn, "trigger", 0},
  { &key_file_init, "init", 0}
};
#endif /* HAVE_PSI_INTERFACE */

PSI_stage_info stage_after_create= { 0, "After create", 0};
PSI_stage_info stage_allocating_local_table= { 0, "allocating local table", 0};
PSI_stage_info stage_alter_inplace_prepare= { 0, "preparing for alter table", 0};
PSI_stage_info stage_alter_inplace= { 0, "altering table", 0};
PSI_stage_info stage_alter_inplace_commit= { 0, "committing alter table to storage engine", 0};
PSI_stage_info stage_changing_master= { 0, "Changing master", 0};
PSI_stage_info stage_checking_master_version= { 0, "Checking master version", 0};
PSI_stage_info stage_checking_permissions= { 0, "checking permissions", 0};
PSI_stage_info stage_checking_privileges_on_cached_query= { 0, "checking privileges on cached query", 0};
PSI_stage_info stage_checking_query_cache_for_query= { 0, "checking query cache for query", 0};
PSI_stage_info stage_cleaning_up= { 0, "cleaning up", 0};
PSI_stage_info stage_closing_tables= { 0, "closing tables", 0};
PSI_stage_info stage_connecting_to_master= { 0, "Connecting to master", 0};
PSI_stage_info stage_converting_heap_to_myisam= { 0, "converting HEAP to MyISAM", 0};
PSI_stage_info stage_copying_to_group_table= { 0, "Copying to group table", 0};
PSI_stage_info stage_copying_to_tmp_table= { 0, "Copying to tmp table", 0};
PSI_stage_info stage_copy_to_tmp_table= { 0, "copy to tmp table", 0};
PSI_stage_info stage_creating_sort_index= { 0, "Creating sort index", 0};
PSI_stage_info stage_creating_table= { 0, "creating table", 0};
PSI_stage_info stage_creating_tmp_table= { 0, "Creating tmp table", 0};
PSI_stage_info stage_deleting_from_main_table= { 0, "deleting from main table", 0};
PSI_stage_info stage_deleting_from_reference_tables= { 0, "deleting from reference tables", 0};
PSI_stage_info stage_discard_or_import_tablespace= { 0, "discard_or_import_tablespace", 0};
PSI_stage_info stage_end= { 0, "end", 0};
PSI_stage_info stage_executing= { 0, "executing", 0};
PSI_stage_info stage_execution_of_init_command= { 0, "Execution of init_command", 0};
PSI_stage_info stage_explaining= { 0, "explaining", 0};
PSI_stage_info stage_finished_reading_one_binlog_switching_to_next_binlog= { 0, "Finished reading one binlog; switching to next binlog", 0};
PSI_stage_info stage_flushing_relay_log_and_master_info_repository= { 0, "Flushing relay log and master info repository.", 0};
PSI_stage_info stage_flushing_relay_log_info_file= { 0, "Flushing relay-log info file.", 0};
PSI_stage_info stage_freeing_items= { 0, "freeing items", 0};
PSI_stage_info stage_fulltext_initialization= { 0, "FULLTEXT initialization", 0};
PSI_stage_info stage_got_handler_lock= { 0, "got handler lock", 0};
PSI_stage_info stage_got_old_table= { 0, "got old table", 0};
PSI_stage_info stage_init= { 0, "init", 0};
PSI_stage_info stage_insert= { 0, "insert", 0};
PSI_stage_info stage_invalidating_query_cache_entries_table= { 0, "invalidating query cache entries (table)", 0};
PSI_stage_info stage_invalidating_query_cache_entries_table_list= { 0, "invalidating query cache entries (table list)", 0};
PSI_stage_info stage_killing_slave= { 0, "Killing slave", 0};
PSI_stage_info stage_logging_slow_query= { 0, "logging slow query", 0};
PSI_stage_info stage_making_temp_file_append_before_load_data= { 0, "Making temporary file (append) before replaying LOAD DATA INFILE", 0};
PSI_stage_info stage_making_temp_file_create_before_load_data= { 0, "Making temporary file (create) before replaying LOAD DATA INFILE", 0};
PSI_stage_info stage_manage_keys= { 0, "manage keys", 0};
PSI_stage_info stage_master_has_sent_all_binlog_to_slave= { 0, "Master has sent all binlog to slave; waiting for more updates", 0};
PSI_stage_info stage_opening_tables= { 0, "Opening tables", 0};
PSI_stage_info stage_optimizing= { 0, "optimizing", 0};
PSI_stage_info stage_preparing= { 0, "preparing", 0};
PSI_stage_info stage_purging_old_relay_logs= { 0, "Purging old relay logs", 0};
PSI_stage_info stage_query_end= { 0, "query end", 0};
PSI_stage_info stage_queueing_master_event_to_the_relay_log= { 0, "Queueing master event to the relay log", 0};
PSI_stage_info stage_reading_event_from_the_relay_log= { 0, "Reading event from the relay log", 0};
PSI_stage_info stage_registering_slave_on_master= { 0, "Registering slave on master", 0};
PSI_stage_info stage_removing_duplicates= { 0, "Removing duplicates", 0};
PSI_stage_info stage_removing_tmp_table= { 0, "removing tmp table", 0};
PSI_stage_info stage_rename= { 0, "rename", 0};
PSI_stage_info stage_rename_result_table= { 0, "rename result table", 0};
PSI_stage_info stage_requesting_binlog_dump= { 0, "Requesting binlog dump", 0};
PSI_stage_info stage_reschedule= { 0, "reschedule", 0};
PSI_stage_info stage_searching_rows_for_update= { 0, "Searching rows for update", 0};
PSI_stage_info stage_sending_binlog_event_to_slave= { 0, "Sending binlog event to slave", 0};
PSI_stage_info stage_sending_cached_result_to_client= { 0, "sending cached result to client", 0};
PSI_stage_info stage_sending_data= { 0, "Sending data", 0};
PSI_stage_info stage_setup= { 0, "setup", 0};
PSI_stage_info stage_slave_has_read_all_relay_log= { 0, "Slave has read all relay log; waiting for more updates", 0};
PSI_stage_info stage_sorting_for_group= { 0, "Sorting for group", 0};
PSI_stage_info stage_sorting_for_order= { 0, "Sorting for order", 0};
PSI_stage_info stage_sorting_result= { 0, "Sorting result", 0};
PSI_stage_info stage_statistics= { 0, "statistics", 0};
PSI_stage_info stage_sql_thd_waiting_until_delay= { 0, "Waiting until MASTER_DELAY seconds after master executed event", 0 };
PSI_stage_info stage_storing_result_in_query_cache= { 0, "storing result in query cache", 0};
PSI_stage_info stage_storing_row_into_queue= { 0, "storing row into queue", 0};
PSI_stage_info stage_system_lock= { 0, "System lock", 0};
PSI_stage_info stage_update= { 0, "update", 0};
PSI_stage_info stage_updating= { 0, "updating", 0};
PSI_stage_info stage_updating_main_table= { 0, "updating main table", 0};
PSI_stage_info stage_updating_reference_tables= { 0, "updating reference tables", 0};
PSI_stage_info stage_upgrading_lock= { 0, "upgrading lock", 0};
PSI_stage_info stage_user_lock= { 0, "User lock", 0};
PSI_stage_info stage_user_sleep= { 0, "User sleep", 0};
PSI_stage_info stage_verifying_table= { 0, "verifying table", 0};
PSI_stage_info stage_waiting_for_gtid_to_be_written_to_binary_log= { 0, "waiting for GTID to be written to binary log", 0};
PSI_stage_info stage_waiting_for_handler_insert= { 0, "waiting for handler insert", 0};
PSI_stage_info stage_waiting_for_handler_lock= { 0, "waiting for handler lock", 0};
PSI_stage_info stage_waiting_for_handler_open= { 0, "waiting for handler open", 0};
PSI_stage_info stage_waiting_for_insert= { 0, "Waiting for INSERT", 0};
PSI_stage_info stage_waiting_for_master_to_send_event= { 0, "Waiting for master to send event", 0};
PSI_stage_info stage_waiting_for_master_update= { 0, "Waiting for master update", 0};
PSI_stage_info stage_waiting_for_relay_log_space= { 0, "Waiting for the slave SQL thread to free enough relay log space", 0};
PSI_stage_info stage_waiting_for_slave_mutex_on_exit= { 0, "Waiting for slave mutex on exit", 0};
PSI_stage_info stage_waiting_for_slave_thread_to_start= { 0, "Waiting for slave thread to start", 0};
PSI_stage_info stage_waiting_for_table_flush= { 0, "Waiting for table flush", 0};
PSI_stage_info stage_waiting_for_query_cache_lock= { 0, "Waiting for query cache lock", 0};
PSI_stage_info stage_waiting_for_the_next_event_in_relay_log= { 0, "Waiting for the next event in relay log", 0};
PSI_stage_info stage_waiting_for_the_slave_thread_to_advance_position= { 0, "Waiting for the slave SQL thread to advance position", 0};
PSI_stage_info stage_waiting_to_finalize_termination= { 0, "Waiting to finalize termination", 0};
PSI_stage_info stage_slave_waiting_workers_to_exit= { 0, "Waiting for workers to exit", 0};
PSI_stage_info stage_slave_waiting_worker_to_release_partition= { 0, "Waiting for Slave Worker to release partition", 0};
PSI_stage_info stage_slave_waiting_worker_to_free_events= { 0, "Waiting for Slave Workers to free pending events", 0};
PSI_stage_info stage_slave_waiting_worker_queue= { 0, "Waiting for Slave Worker queue", 0};
PSI_stage_info stage_slave_waiting_event_from_coordinator= { 0, "Waiting for an event from Coordinator", 0};
PSI_stage_info stage_slave_waiting_for_workers_to_finish= { 0, "Waiting for slave workers to finish.", 0};
PSI_stage_info stage_starting= { 0, "starting", 0};
#ifdef HAVE_PSI_INTERFACE

PSI_stage_info *all_server_stages[]=
{
  & stage_after_create,
  & stage_allocating_local_table,
  & stage_alter_inplace_prepare,
  & stage_alter_inplace,
  & stage_alter_inplace_commit,
  & stage_changing_master,
  & stage_checking_master_version,
  & stage_checking_permissions,
  & stage_checking_privileges_on_cached_query,
  & stage_checking_query_cache_for_query,
  & stage_cleaning_up,
  & stage_closing_tables,
  & stage_connecting_to_master,
  & stage_converting_heap_to_myisam,
  & stage_copying_to_group_table,
  & stage_copying_to_tmp_table,
  & stage_copy_to_tmp_table,
  & stage_creating_sort_index,
  & stage_creating_table,
  & stage_creating_tmp_table,
  & stage_deleting_from_main_table,
  & stage_deleting_from_reference_tables,
  & stage_discard_or_import_tablespace,
  & stage_end,
  & stage_executing,
  & stage_execution_of_init_command,
  & stage_explaining,
  & stage_finished_reading_one_binlog_switching_to_next_binlog,
  & stage_flushing_relay_log_and_master_info_repository,
  & stage_flushing_relay_log_info_file,
  & stage_freeing_items,
  & stage_fulltext_initialization,
  & stage_got_handler_lock,
  & stage_got_old_table,
  & stage_init,
  & stage_insert,
  & stage_invalidating_query_cache_entries_table,
  & stage_invalidating_query_cache_entries_table_list,
  & stage_killing_slave,
  & stage_logging_slow_query,
  & stage_making_temp_file_append_before_load_data,
  & stage_making_temp_file_create_before_load_data,
  & stage_manage_keys,
  & stage_master_has_sent_all_binlog_to_slave,
  & stage_opening_tables,
  & stage_optimizing,
  & stage_preparing,
  & stage_purging_old_relay_logs,
  & stage_query_end,
  & stage_queueing_master_event_to_the_relay_log,
  & stage_reading_event_from_the_relay_log,
  & stage_registering_slave_on_master,
  & stage_removing_duplicates,
  & stage_removing_tmp_table,
  & stage_rename,
  & stage_rename_result_table,
  & stage_requesting_binlog_dump,
  & stage_reschedule,
  & stage_searching_rows_for_update,
  & stage_sending_binlog_event_to_slave,
  & stage_sending_cached_result_to_client,
  & stage_sending_data,
  & stage_setup,
  & stage_slave_has_read_all_relay_log,
  & stage_sorting_for_group,
  & stage_sorting_for_order,
  & stage_sorting_result,
  & stage_sql_thd_waiting_until_delay,
  & stage_statistics,
  & stage_storing_result_in_query_cache,
  & stage_storing_row_into_queue,
  & stage_system_lock,
  & stage_update,
  & stage_updating,
  & stage_updating_main_table,
  & stage_updating_reference_tables,
  & stage_upgrading_lock,
  & stage_user_lock,
  & stage_user_sleep,
  & stage_verifying_table,
  & stage_waiting_for_handler_insert,
  & stage_waiting_for_handler_lock,
  & stage_waiting_for_handler_open,
  & stage_waiting_for_insert,
  & stage_waiting_for_master_to_send_event,
  & stage_waiting_for_master_update,
  & stage_waiting_for_slave_mutex_on_exit,
  & stage_waiting_for_slave_thread_to_start,
  & stage_waiting_for_table_flush,
  & stage_waiting_for_query_cache_lock,
  & stage_waiting_for_the_next_event_in_relay_log,
  & stage_waiting_for_the_slave_thread_to_advance_position,
  & stage_waiting_to_finalize_termination,
  & stage_starting
};

PSI_socket_key key_socket_tcpip, key_socket_unix, key_socket_client_connection;

static PSI_socket_info all_server_sockets[]=
{
  { &key_socket_tcpip, "server_tcpip_socket", PSI_FLAG_GLOBAL},
  { &key_socket_unix, "server_unix_socket", PSI_FLAG_GLOBAL},
  { &key_socket_client_connection, "client_connection", 0}
};
#endif /* HAVE_PSI_INTERFACE */

PSI_memory_key key_memory_buffered_logs;
PSI_memory_key key_memory_locked_table_list;
PSI_memory_key key_memory_thd_transactions;
PSI_memory_key key_memory_delegate;
PSI_memory_key key_memory_acl_mem;
PSI_memory_key key_memory_acl_memex;
PSI_memory_key key_memory_thd_main_mem_root;
PSI_memory_key key_memory_help;
PSI_memory_key key_memory_new_frm_mem;
PSI_memory_key key_memory_table_share;
PSI_memory_key key_memory_gdl;
PSI_memory_key key_memory_table_triggers_list;
PSI_memory_key key_memory_servers;
PSI_memory_key key_memory_prepared_statement_main_mem_root;
PSI_memory_key key_memory_protocol_rset_root;
PSI_memory_key key_memory_warning_info_warn_root;
PSI_memory_key key_memory_sp_head_main_root;
PSI_memory_key key_memory_sp_head_execute_root;
PSI_memory_key key_memory_sp_head_call_root;
PSI_memory_key key_memory_table_mapping_root;
PSI_memory_key key_memory_quick_range_select_root;
PSI_memory_key key_memory_quick_index_merge_root;
PSI_memory_key key_memory_quick_ror_intersect_select_root;
PSI_memory_key key_memory_quick_ror_union_select_root;
PSI_memory_key key_memory_quick_group_min_max_select_root;
PSI_memory_key key_memory_sql_select_test_quick_select_exec;
PSI_memory_key key_memory_prune_partitions_exec;
PSI_memory_key key_memory_binlog_recover_exec;
PSI_memory_key key_memory_blob_mem_storage;
PSI_memory_key key_memory_NAMED_ILINK_name;
PSI_memory_key key_memory_Sys_var_charptr_value;
PSI_memory_key key_memory_queue_item;
PSI_memory_key key_memory_THD_db;
PSI_memory_key key_memory_user_var_entry;
PSI_memory_key key_memory_Slave_job_group_group_relay_log_name;
PSI_memory_key key_memory_Relay_log_info_group_relay_log_name;
PSI_memory_key key_memory_binlog_cache_mngr;
PSI_memory_key key_memory_Row_data_memory_memory;
PSI_memory_key key_memory_Gtid_state_to_string;
PSI_memory_key key_memory_Owned_gtids_to_string;
PSI_memory_key key_memory_Sort_param_tmp_buffer;
PSI_memory_key key_memory_Filesort_info_merge;
PSI_memory_key key_memory_Filesort_info_record_pointers;
PSI_memory_key key_memory_handler_errmsgs;
PSI_memory_key key_memory_handlerton;
PSI_memory_key key_memory_XID;
PSI_memory_key key_memory_host_cache_hostname;
PSI_memory_key key_memory_user_var_entry_value;
PSI_memory_key key_memory_User_level_lock_key;
PSI_memory_key key_memory_MYSQL_LOG_name;
PSI_memory_key key_memory_TC_LOG_MMAP_pages;
PSI_memory_key key_memory_my_bitmap_map;
PSI_memory_key key_memory_QUICK_RANGE_SELECT_mrr_buf_desc;
PSI_memory_key key_memory_Event_queue_element_for_exec_names;
PSI_memory_key key_memory_my_str_malloc;
PSI_memory_key key_memory_MYSQL_BIN_LOG_basename;
PSI_memory_key key_memory_MYSQL_BIN_LOG_index;
PSI_memory_key key_memory_MYSQL_RELAY_LOG_basename;
PSI_memory_key key_memory_MYSQL_RELAY_LOG_index;
PSI_memory_key key_memory_rpl_filter;
PSI_memory_key key_memory_errmsgs;
PSI_memory_key key_memory_Gcalc_dyn_list_block;
PSI_memory_key key_memory_Gis_read_stream_err_msg;
PSI_memory_key key_memory_KEY_CACHE;
PSI_memory_key key_memory_MYSQL_LOCK;
PSI_memory_key key_memory_Event_scheduler_scheduler_param;
PSI_memory_key key_memory_Owned_gtids_sidno_to_hash;
PSI_memory_key key_memory_Mutex_cond_array_Mutex_cond;
PSI_memory_key key_memory_TABLE_RULE_ENT;
PSI_memory_key key_memory_partition_file;
PSI_memory_key key_memory_partition_engine_array;
PSI_memory_key key_memory_ha_partition_PART_NAME_DEF;
PSI_memory_key key_memory_ha_partition_part_ids;
PSI_memory_key key_memory_ha_partition_ordered_rec_buffer;
PSI_memory_key key_memory_Rpl_info_table;
PSI_memory_key key_memory_Rpl_info_file_buffer;
PSI_memory_key key_memory_db_worker_hash_entry;
PSI_memory_key key_memory_rpl_slave_check_temp_dir;
PSI_memory_key key_memory_rpl_slave_command_buffer;
PSI_memory_key key_memory_binlog_ver_1_event;
PSI_memory_key key_memory_SLAVE_INFO;
PSI_memory_key key_memory_binlog_pos;
PSI_memory_key key_memory_HASH_ROW_ENTRY;
PSI_memory_key key_memory_binlog_statement_buffer;
PSI_memory_key key_memory_partition_syntax_buffer;
PSI_memory_key key_memory_READ_INFO;
PSI_memory_key key_memory_JOIN_CACHE;
PSI_memory_key key_memory_TABLE_sort_io_cache;
PSI_memory_key key_memory_frm;
PSI_memory_key key_memory_Unique_sort_buffer;
PSI_memory_key key_memory_Unique_merge_buffer;
PSI_memory_key key_memory_TABLE;
PSI_memory_key key_memory_frm_extra_segment_buff;
PSI_memory_key key_memory_frm_form_pos;
PSI_memory_key key_memory_frm_string;
PSI_memory_key key_memory_LOG_name;
PSI_memory_key key_memory_DATE_TIME_FORMAT;
PSI_memory_key key_memory_DDL_LOG_MEMORY_ENTRY;
PSI_memory_key key_memory_ST_SCHEMA_TABLE;
PSI_memory_key key_memory_ignored_db;
PSI_memory_key key_memory_PROFILE;
PSI_memory_key key_memory_st_mysql_plugin_dl;
PSI_memory_key key_memory_st_mysql_plugin;
PSI_memory_key key_memory_global_system_variables;
PSI_memory_key key_memory_THD_variables;
PSI_memory_key key_memory_Security_context;
PSI_memory_key key_memory_shared_memory_name;
PSI_memory_key key_memory_bison_stack;
PSI_memory_key key_memory_THD_handler_tables_hash;
PSI_memory_key key_memory_mysql_manager;
PSI_memory_key key_memory_hash_index_key_buffer;
PSI_memory_key key_memory_dboptions_hash;
PSI_memory_key key_memory_user_conn;
PSI_memory_key key_memory_LOG_POS_COORD;
PSI_memory_key key_memory_XID_STATE;
PSI_memory_key key_memory_MPVIO_EXT_auth_info;
PSI_memory_key key_memory_opt_bin_logname;
PSI_memory_key key_memory_Query_cache;
PSI_memory_key key_memory_READ_RECORD_cache;
PSI_memory_key key_memory_Quick_ranges;
PSI_memory_key key_memory_File_query_log_name;
PSI_memory_key key_memory_Table_trigger_dispatcher;
#ifdef HAVE_MY_TIMER
PSI_memory_key key_memory_thd_timer;
#endif
PSI_memory_key key_memory_THD_Session_tracker;
PSI_memory_key key_memory_THD_Session_sysvar_resource_manager;

#ifdef HAVE_PSI_INTERFACE
static PSI_memory_info all_server_memory[]=
{
  { &key_memory_buffered_logs, "buffered_logs", PSI_FLAG_GLOBAL},
  { &key_memory_locked_table_list, "Locked_tables_list::m_locked_tables_root", 0},
  { &key_memory_thd_transactions, "THD::transactions::mem_root", PSI_FLAG_THREAD},
  { &key_memory_delegate, "Delegate::memroot", 0},
  { &key_memory_acl_mem, "sql_acl_mem", PSI_FLAG_GLOBAL},
  { &key_memory_acl_memex, "sql_acl_memex", PSI_FLAG_GLOBAL},
  { &key_memory_thd_main_mem_root, "thd::main_mem_root", PSI_FLAG_THREAD},
  { &key_memory_help, "help", 0},
  { &key_memory_new_frm_mem, "new_frm_mem", 0},
  { &key_memory_table_share, "TABLE_SHARE::mem_root", 0},
  { &key_memory_gdl, "gdl", 0},
  { &key_memory_table_triggers_list, "Table_triggers_list", 0},
  { &key_memory_servers, "servers", 0},
  { &key_memory_prepared_statement_main_mem_root, "Prepared_statement::main_mem_root", PSI_FLAG_THREAD},
  { &key_memory_protocol_rset_root, "Protocol_local::m_rset_root", PSI_FLAG_THREAD},
  { &key_memory_warning_info_warn_root, "Warning_info::m_warn_root", PSI_FLAG_THREAD},
  { &key_memory_sp_head_main_root, "sp_head::main_mem_root", 0},
  { &key_memory_sp_head_execute_root, "sp_head::execute_mem_root", PSI_FLAG_THREAD},
  { &key_memory_sp_head_call_root, "sp_head::call_mem_root", PSI_FLAG_THREAD},
  { &key_memory_table_mapping_root, "table_mapping::m_mem_root", 0},
  { &key_memory_quick_range_select_root, "QUICK_RANGE_SELECT::alloc", PSI_FLAG_THREAD},
  { &key_memory_quick_index_merge_root, "QUICK_INDEX_MERGE_SELECT::alloc", PSI_FLAG_THREAD},
  { &key_memory_quick_ror_intersect_select_root, "QUICK_ROR_INTERSECT_SELECT::alloc", PSI_FLAG_THREAD},
  { &key_memory_quick_ror_union_select_root, "QUICK_ROR_UNION_SELECT::alloc", PSI_FLAG_THREAD},
  { &key_memory_quick_group_min_max_select_root, "QUICK_GROUP_MIN_MAX_SELECT::alloc", PSI_FLAG_THREAD},
  { &key_memory_sql_select_test_quick_select_exec, "SQL_SELECT::test_quick_select", PSI_FLAG_THREAD},
  { &key_memory_prune_partitions_exec, "prune_partitions::exec", 0},
  { &key_memory_binlog_recover_exec, "MYSQL_BIN_LOG::recover", 0},
  { &key_memory_blob_mem_storage, "Blob_mem_storage::storage", 0},

  { &key_memory_NAMED_ILINK_name, "NAMED_ILINK::name", 0},
  { &key_memory_String_value, "String::value", 0},
  { &key_memory_Sys_var_charptr_value, "Sys_var_charptr::value", 0},
  { &key_memory_queue_item, "Queue::queue_item", 0},
  { &key_memory_THD_db, "THD::db", 0},
  { &key_memory_user_var_entry, "user_var_entry", 0},
  { &key_memory_Slave_job_group_group_relay_log_name, "Slave_job_group::group_relay_log_name", 0},
  { &key_memory_Relay_log_info_group_relay_log_name, "Relay_log_info::group_relay_log_name", 0},
  { &key_memory_binlog_cache_mngr, "binlog_cache_mngr", 0},
  { &key_memory_Row_data_memory_memory, "Row_data_memory::memory", 0},

  { &key_memory_Gtid_set_to_string, "Gtid_set::to_string", 0},
  { &key_memory_Gtid_state_to_string, "Gtid_state::to_string", 0},
  { &key_memory_Owned_gtids_to_string, "Owned_gtids::to_string", 0},
  { &key_memory_log_event, "Log_event", 0},
  { &key_memory_Incident_log_event_message, "Incident_log_event::message", 0},
  { &key_memory_Rows_query_log_event_rows_query, "Rows_query_log_event::rows_query", 0},

  { &key_memory_Sort_param_tmp_buffer, "Sort_param::tmp_buffer", 0},
  { &key_memory_Filesort_info_merge, "Filesort_info::merge", 0},
  { &key_memory_Filesort_info_record_pointers, "Filesort_info::record_pointers", 0},
  { &key_memory_Filesort_buffer_sort_keys, "Filesort_buffer::sort_keys", 0},
  { &key_memory_handler_errmsgs, "handler::errmsgs", 0},
  { &key_memory_handlerton, "handlerton", 0},
  { &key_memory_XID, "XID", 0},
  { &key_memory_host_cache_hostname, "host_cache::hostname", 0},
  { &key_memory_user_var_entry_value, "user_var_entry::value", 0},
  { &key_memory_User_level_lock_key, "User_level_lock::key", 0},
  { &key_memory_MYSQL_LOG_name, "MYSQL_LOG::name", 0},
  { &key_memory_TC_LOG_MMAP_pages, "TC_LOG_MMAP::pages", 0},
  { &key_memory_my_bitmap_map, "my_bitmap_map", 0},
  { &key_memory_QUICK_RANGE_SELECT_mrr_buf_desc, "QUICK_RANGE_SELECT::mrr_buf_desc", 0},
  { &key_memory_Event_queue_element_for_exec_names, "Event_queue_element_for_exec::names", 0},
  { &key_memory_my_str_malloc, "my_str_malloc", 0},
  { &key_memory_MYSQL_BIN_LOG_basename, "MYSQL_BIN_LOG::basename", 0},
  { &key_memory_MYSQL_BIN_LOG_index, "MYSQL_BIN_LOG::index", 0},
  { &key_memory_MYSQL_RELAY_LOG_basename, "MYSQL_RELAY_LOG::basename", 0},
  { &key_memory_MYSQL_RELAY_LOG_index, "MYSQL_RELAY_LOG::index", 0},
  { &key_memory_rpl_filter, "rpl_filter memory", 0},
  { &key_memory_errmsgs, "errmsgs", 0},
  { &key_memory_Gcalc_dyn_list_block, "Gcalc_dyn_list::block", 0},
  { &key_memory_Gis_read_stream_err_msg, "Gis_read_stream::err_msg", 0},
  { &key_memory_KEY_CACHE, "KEY_CACHE", 0},
  { &key_memory_MYSQL_LOCK, "MYSQL_LOCK", 0},
  { &key_memory_NET_buff, "NET::buff", 0},
  { &key_memory_NET_compress_packet, "NET::compress_packet", 0},
  { &key_memory_Event_scheduler_scheduler_param, "Event_scheduler::scheduler_param", 0},
  { &key_memory_Gtid_set_Interval_chunk, "Gtid_set::Interval_chunk", 0},
  { &key_memory_Owned_gtids_sidno_to_hash, "Owned_gtids::sidno_to_hash", 0},
  { &key_memory_Sid_map_Node, "Sid_map::Node", 0},
  { &key_memory_Mutex_cond_array_Mutex_cond, "Mutex_cond_array::Mutex_cond", 0},
  { &key_memory_TABLE_RULE_ENT, "TABLE_RULE_ENT", 0},
  { &key_memory_partition_file, "ha_partition::file", 0},
  { &key_memory_partition_engine_array, "ha_partition::engine_array", 0},
  { &key_memory_ha_partition_PART_NAME_DEF, "ha_partition::PART_NAME_DEF", 0},
  { &key_memory_ha_partition_part_ids, "ha_partition::part_ids", 0},
  { &key_memory_ha_partition_ordered_rec_buffer, "ha_partition::ordered_rec_buffer", 0},

  { &key_memory_Rpl_info_table, "Rpl_info_table", 0},
  { &key_memory_Rpl_info_file_buffer, "Rpl_info_file::buffer", 0},
  { &key_memory_db_worker_hash_entry, "db_worker_hash_entry", 0},
  { &key_memory_rpl_slave_check_temp_dir, "rpl_slave::check_temp_dir", 0},
  { &key_memory_rpl_slave_command_buffer, "rpl_slave::command_buffer", 0},
  { &key_memory_binlog_ver_1_event, "binlog_ver_1_event", 0},
  { &key_memory_SLAVE_INFO, "SLAVE_INFO", 0},
  { &key_memory_binlog_pos, "binlog_pos", 0},
  { &key_memory_HASH_ROW_ENTRY, "HASH_ROW_ENTRY", 0},
  { &key_memory_binlog_statement_buffer, "binlog_statement_buffer", 0},
  { &key_memory_partition_syntax_buffer, "partition_syntax_buffer", 0},
  { &key_memory_READ_INFO, "READ_INFO", 0},
  { &key_memory_JOIN_CACHE, "JOIN_CACHE", 0},
  { &key_memory_TABLE_sort_io_cache, "TABLE::sort_io_cache", 0},
  { &key_memory_frm, "frm", 0},
  { &key_memory_Unique_sort_buffer, "Unique::sort_buffer", 0},
  { &key_memory_Unique_merge_buffer, "Unique::merge_buffer", 0},
  { &key_memory_TABLE, "TABLE", 0},
  { &key_memory_frm_extra_segment_buff, "frm::extra_segment_buff", 0},
  { &key_memory_frm_form_pos, "frm::form_pos", 0},
  { &key_memory_frm_string, "frm::string", 0},
  { &key_memory_LOG_name, "LOG_name", 0},
  { &key_memory_DATE_TIME_FORMAT, "DATE_TIME_FORMAT", 0},
  { &key_memory_DDL_LOG_MEMORY_ENTRY, "DDL_LOG_MEMORY_ENTRY", 0},
  { &key_memory_ST_SCHEMA_TABLE, "ST_SCHEMA_TABLE", 0},
  { &key_memory_ignored_db, "ignored_db", 0},
  { &key_memory_PROFILE, "PROFILE", 0},
  { &key_memory_global_system_variables, "global_system_variables", 0},
  { &key_memory_THD_variables, "THD::variables", 0},
  { &key_memory_Security_context, "Security_context", 0},
  { &key_memory_shared_memory_name, "Shared_memory_name", 0},
  { &key_memory_bison_stack, "bison_stack", 0},
  { &key_memory_THD_handler_tables_hash, "THD::handler_tables_hash", 0},
  { &key_memory_mysql_manager, "mysql_manager", 0},
  { &key_memory_hash_index_key_buffer, "hash_index_key_buffer", 0},
  { &key_memory_dboptions_hash, "dboptions_hash", 0},
  { &key_memory_user_conn, "user_conn", 0},
  { &key_memory_LOG_POS_COORD, "LOG_POS_COORD", 0},
  { &key_memory_XID_STATE, "XID_STATE", 0},
  { &key_memory_MPVIO_EXT_auth_info, "MPVIO_EXT::auth_info", 0},
  { &key_memory_opt_bin_logname, "opt_bin_logname", 0},
  { &key_memory_Query_cache, "Query_cache", 0},
  { &key_memory_READ_RECORD_cache, "READ_RECORD_cache", 0},
  { &key_memory_Quick_ranges, "Quick_ranges", 0},
  { &key_memory_File_query_log_name, "File_query_log::name", 0},
  { &key_memory_Table_trigger_dispatcher, "Table_trigger_dispatcher::m_mem_root", 0},
#ifdef HAVE_MY_TIMER
  { &key_memory_thd_timer, "thd_timer", 0},
#endif
  { &key_memory_Table_trigger_dispatcher, "Table_trigger_dispatcher::m_mem_root", 0},
  { &key_memory_THD_Session_tracker, "THD::Session_tracker", 0},
  { &key_memory_THD_Session_sysvar_resource_manager, "THD::Session_sysvar_resource_manager", 0}
};

/* TODO: find a good header */
extern "C" void init_client_psi_keys(void);

/**
  Initialise all the performance schema instrumentation points
  used by the server.
*/
void init_server_psi_keys(void)
{
  const char* category= "sql";
  int count;

  count= array_elements(all_server_mutexes);
  mysql_mutex_register(category, all_server_mutexes, count);

  count= array_elements(all_server_rwlocks);
  mysql_rwlock_register(category, all_server_rwlocks, count);

  count= array_elements(all_server_conds);
  mysql_cond_register(category, all_server_conds, count);

  count= array_elements(all_server_threads);
  mysql_thread_register(category, all_server_threads, count);

  count= array_elements(all_server_files);
  mysql_file_register(category, all_server_files, count);

  count= array_elements(all_server_stages);
  mysql_stage_register(category, all_server_stages, count);

  count= array_elements(all_server_sockets);
  mysql_socket_register(category, all_server_sockets, count);

  count= array_elements(all_server_memory);
  mysql_memory_register(category, all_server_memory, count);

#ifdef HAVE_PSI_STATEMENT_INTERFACE
  init_sql_statement_info();
  count= array_elements(sql_statement_info);
  mysql_statement_register(category, sql_statement_info, count);

  init_sp_psi_keys();

  init_scheduler_psi_keys();

  category= "com";
  init_com_statement_info();

  /*
    Register [0 .. COM_QUERY - 1] as "statement/com/..."
  */
  count= (int) COM_QUERY;
  mysql_statement_register(category, com_statement_info, count);

  /*
    Register [COM_QUERY + 1 .. COM_END] as "statement/com/..."
  */
  count= (int) COM_END - (int) COM_QUERY;
  mysql_statement_register(category, & com_statement_info[(int) COM_QUERY + 1], count);

  category= "abstract";
  /*
    Register [COM_QUERY] as "statement/abstract/com_query"
  */
  mysql_statement_register(category, & com_statement_info[(int) COM_QUERY], 1);

  /*
    When a new packet is received,
    it is instrumented as "statement/abstract/new_packet".
    Based on the packet type found, it later mutates to the
    proper narrow type, for example
    "statement/abstract/query" or "statement/com/ping".
    In cases of "statement/abstract/query", SQL queries are given to
    the parser, which mutates the statement type to an even more
    narrow classification, for example "statement/sql/select".
  */
  stmt_info_new_packet.m_key= 0;
  stmt_info_new_packet.m_name= "new_packet";
  stmt_info_new_packet.m_flags= PSI_FLAG_MUTABLE;
  mysql_statement_register(category, &stmt_info_new_packet, 1);

  /*
    Statements processed from the relay log are initially instrumented as
    "statement/abstract/relay_log". The parser will mutate the statement type to
    a more specific classification, for example "statement/sql/insert".
  */
  stmt_info_rpl.m_key= 0;
  stmt_info_rpl.m_name= "relay_log";
  stmt_info_rpl.m_flags= PSI_FLAG_MUTABLE;
  mysql_statement_register(category, &stmt_info_rpl, 1);
#endif

  /* Common client and server code. */
  init_client_psi_keys();
  /* Vio */
  init_vio_psi_keys();
}

#endif /* HAVE_PSI_INTERFACE */

