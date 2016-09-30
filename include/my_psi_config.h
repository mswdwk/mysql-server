/*
   Copyright (c) 2001, 2016, Oracle and/or its affiliates. All rights reserved.

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

#ifndef MY_PSI_CONFIG_INCLUDED
#define MY_PSI_CONFIG_INCLUDED

/**
  @file include/my_psi_config.h
  Defines various enable/disable and HAVE_ macros related to the
  performance schema instrumentation system, without pulling in
  any system \#include files like "my_global.h" does (which breaks the
  ABI checker).

*/

#include "my_config.h"

#ifdef WITH_PERFSCHEMA_STORAGE_ENGINE
#ifdef EMBEDDED_LIBRARY

#ifndef DISABLE_PSI_THREAD
#define DISABLE_PSI_THREAD
#endif

#ifndef DISABLE_PSI_MUTEX
#define DISABLE_PSI_MUTEX
#endif

#ifndef DISABLE_PSI_RWLOCK
#define DISABLE_PSI_RWLOCK
#endif

#ifndef DISABLE_PSI_COND
#define DISABLE_PSI_COND
#endif

#ifndef DISABLE_PSI_FILE
#define DISABLE_PSI_FILE
#endif

#ifndef DISABLE_PSI_TABLE
#define DISABLE_PSI_TABLE
#endif

#ifndef DISABLE_PSI_SOCKET
#define DISABLE_PSI_SOCKET
#endif

#ifndef DISABLE_PSI_STAGE
#define DISABLE_PSI_STAGE
#endif

#ifndef DISABLE_PSI_STATEMENT
#define DISABLE_PSI_STATEMENT
#endif

#ifndef DISABLE_PSI_SP
#define DISABLE_PSI_SP
#endif

#ifndef DISABLE_PSI_PS
#define DISABLE_PSI_PS
#endif

#ifndef DISABLE_PSI_ERROR
#define DISABLE_PSI_ERROR
#endif

#ifndef DISABLE_PSI_IDLE
#define DISABLE_PSI_IDLE
#endif

#ifndef DISABLE_PSI_STATEMENT_DIGEST
#define DISABLE_PSI_STATEMENT_DIGEST
#endif

#ifndef DISABLE_PSI_METADATA
#define DISABLE_PSI_METADATA
#endif

#ifndef DISABLE_PSI_MEMORY
#define DISABLE_PSI_MEMORY
#endif

#ifndef DISABLE_PSI_TRANSACTION
#define DISABLE_PSI_TRANSACTION
#endif

#ifndef DISABLE_PSI_DATA_LOCK
#define DISABLE_PSI_DATA_LOCK
#endif

#endif /* EMBEDDED_LIBRARY */
#endif /* WITH_PERFSCHEMA_STORAGE_ENGINE */

#ifdef WITH_PERFSCHEMA_STORAGE_ENGINE
#define HAVE_PSI_INTERFACE
#endif /* WITH_PERFSCHEMA_STORAGE_ENGINE */

#ifdef HAVE_PSI_INTERFACE

 /**
  @def DISABLE_PSI_MUTEX
  Compiling option to disable the mutex instrumentation.
  This option is mostly intended to be used during development,
  when doing special builds with only a subset of the performance schema instrumentation,
  for code analysis / profiling / performance tuning of a specific instrumentation alone.
  @sa DISABLE_PSI_RWLOCK
  @sa DISABLE_PSI_COND
  @sa DISABLE_PSI_FILE
  @sa DISABLE_PSI_THREAD
  @sa DISABLE_PSI_TABLE
  @sa DISABLE_PSI_STAGE
  @sa DISABLE_PSI_STATEMENT
  @sa DISABLE_PSI_SP
  @sa DISABLE_PSI_PS
  @sa DISABLE_PSI_STATEMENT_DIGEST
  @sa DISABLE_PSI_SOCKET
  @sa DISABLE_PSI_MEMORY
  @sa DISABLE_PSI_ERROR
  @sa DISABLE_PSI_IDLE
  @sa DISABLE_PSI_METADATA
  @sa DISABLE_PSI_TRANSACTION
  @sa DISABLE_PSI_DATA_LOCK
*/

#ifndef DISABLE_PSI_MUTEX
#define HAVE_PSI_MUTEX_INTERFACE
#endif /* DISABLE_PSI_MUTEX */

/**
  @def DISABLE_PSI_RWLOCK
  Compiling option to disable the rwlock instrumentation.
  @sa DISABLE_PSI_MUTEX
*/

#ifndef DISABLE_PSI_RWLOCK
#define HAVE_PSI_RWLOCK_INTERFACE
#endif /* DISABLE_PSI_RWLOCK */

/**
  @def DISABLE_PSI_COND
  Compiling option to disable the cond instrumentation.
  @sa DISABLE_PSI_MUTEX
*/

#ifndef DISABLE_PSI_COND
#define HAVE_PSI_COND_INTERFACE
#endif /* DISABLE_PSI_COND */

/**
  @def DISABLE_PSI_FILE
  Compiling option to disable the file instrumentation.
  @sa DISABLE_PSI_MUTEX
*/

#ifndef DISABLE_PSI_FILE
#define HAVE_PSI_FILE_INTERFACE
#endif /* DISABLE_PSI_FILE */

/**
  @def DISABLE_PSI_THREAD
  Compiling option to disable the thread instrumentation.
  @sa DISABLE_PSI_MUTEX
*/

#ifndef DISABLE_PSI_THREAD
#define HAVE_PSI_THREAD_INTERFACE
#endif /* DISABLE_PSI_THREAD */

/**
  @def DISABLE_PSI_TABLE
  Compiling option to disable the table instrumentation.
  @sa DISABLE_PSI_MUTEX
*/

#ifndef DISABLE_PSI_TABLE
#define HAVE_PSI_TABLE_INTERFACE
#endif /* DISABLE_PSI_TABLE */

/**
  @def DISABLE_PSI_STAGE
  Compiling option to disable the stage instrumentation.
  @sa DISABLE_PSI_MUTEX
*/

#ifndef DISABLE_PSI_STAGE
#define HAVE_PSI_STAGE_INTERFACE
#endif /* DISABLE_PSI_STAGE */

/**
  @def DISABLE_PSI_STATEMENT
  Compiling option to disable the statement instrumentation.
  @sa DISABLE_PSI_MUTEX
*/

#ifndef DISABLE_PSI_STATEMENT
#define HAVE_PSI_STATEMENT_INTERFACE
#endif /* DISABLE_PSI_STATEMENT */

/**
  @def DISABLE_PSI_SP
  Compiling option to disable the stored program instrumentation.
  @sa DISABLE_PSI_MUTEX
*/

#ifndef DISABLE_PSI_SP
#define HAVE_PSI_SP_INTERFACE
#endif /* DISABLE_PSI_SP */

/**
  @def DISABLE_PSI_PS
  Compiling option to disable the prepared statement instrumentation.
  @sa DISABLE_PSI_MUTEX
*/

#ifndef DISABLE_PSI_STATEMENT
#ifndef DISABLE_PSI_PS
#define HAVE_PSI_PS_INTERFACE
#endif /* DISABLE_PSI_PS */
#endif /* DISABLE_PSI_STATEMENT */

/**
  @def DISABLE_PSI_STATEMENT_DIGEST
  Compiling option to disable the statement digest instrumentation.
*/

#ifndef DISABLE_PSI_STATEMENT
#ifndef DISABLE_PSI_STATEMENT_DIGEST
#define HAVE_PSI_STATEMENT_DIGEST_INTERFACE
#endif /* DISABLE_PSI_STATEMENT_DIGEST */
#endif /* DISABLE_PSI_STATEMENT */

/**
  @def DISABLE_PSI_TRANSACTION
  Compiling option to disable the transaction instrumentation.
  @sa DISABLE_PSI_MUTEX
*/

#ifndef DISABLE_PSI_TRANSACTION
#define HAVE_PSI_TRANSACTION_INTERFACE
#endif /* DISABLE_PSI_TRANSACTION */

/**
  @def DISABLE_PSI_SOCKET
  Compiling option to disable the statement instrumentation.
  @sa DISABLE_PSI_MUTEX
*/

#ifndef DISABLE_PSI_SOCKET
#define HAVE_PSI_SOCKET_INTERFACE
#endif /* DISABLE_PSI_SOCKET */

/**
  @def DISABLE_PSI_MEMORY
  Compiling option to disable the memory instrumentation.
  @sa DISABLE_PSI_MUTEX
*/

#ifndef DISABLE_PSI_MEMORY
#define HAVE_PSI_MEMORY_INTERFACE
#endif /* DISABLE_PSI_MEMORY */

/**
  @def DISABLE_PSI_ERROR
  Compiling option to disable the error instrumentation.
  @sa DISABLE_PSI_MUTEX
*/

#ifndef DISABLE_PSI_ERROR
#define HAVE_PSI_ERROR_INTERFACE
#endif /* DISABLE_PSI_ERROR */

/**
  @def DISABLE_PSI_IDLE
  Compiling option to disable the idle instrumentation.
  @sa DISABLE_PSI_MUTEX
*/

#ifndef DISABLE_PSI_IDLE
#define HAVE_PSI_IDLE_INTERFACE
#endif /* DISABLE_PSI_IDLE */

/**
  @def DISABLE_PSI_METADATA
  Compiling option to disable the metadata instrumentation.
  @sa DISABLE_PSI_MUTEX
*/

#ifndef DISABLE_PSI_METADATA
#define HAVE_PSI_METADATA_INTERFACE
#endif /* DISABLE_PSI_METADATA */

/**
  @def DISABLE_PSI_DATA_LOCK
  Compiling option to disable the data lock instrumentation.
  @sa DISABLE_PSI_MUTEX
*/

#ifndef DISABLE_PSI_DATA_LOCK
#define HAVE_PSI_DATA_LOCK_INTERFACE
#endif /* DISABLE_PSI_DATA_LOCK */

#endif /* HAVE_PSI_INTERFACE */

#endif  // MY_PSI_CONFIG_INCLUDED
