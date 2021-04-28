/* Copyright (c) 2000, 2021, Oracle and/or its affiliates.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License, version 2.0,
   as published by the Free Software Foundation.

   This program is also distributed with certain software (including
   but not limited to OpenSSL) that is licensed under separate terms,
   as designated in a particular file or component or in included license
   documentation.  The authors of MySQL hereby grant you an additional
   permission to link the program and your derivative works with the
   separately licensed software that they have included with MySQL.

   Without limiting anything contained in the foregoing, this file,
   which is part of C Driver for MySQL (Connector/C), is also subject to the
   Universal FOSS Exception, version 1.0, a copy of which can be found at
   http://oss.oracle.com/licenses/universal-foss-exception.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License, version 2.0, for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

/**
  @file mysys/my_thread.cc
*/

#include "my_config.h"

#ifdef HAVE_PTHREAD_SETNAME_NP_LINUX
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <pthread.h>
#endif /* HAVE_PTHREAD_SETNAME_NP_LINUX */

#ifdef HAVE_PTHREAD_SETNAME_NP_MACOS
#include <pthread.h>
#endif /* HAVE_PTHREAD_SETNAME_NP_MACOS */

#ifdef HAVE_SET_THREAD_DESCRIPTION
#include <windows.h>

#include <processthreadsapi.h>

#include <stringapiset.h>
#endif /* HAVE_SET_THREAD_DESCRIPTION */

#include "my_thread.h"
#include "mysql/components/services/my_thread_bits.h"

#include <string.h>

#ifdef _WIN32
#include <errno.h>
#include <process.h>
#include <signal.h>
#include "my_sys.h" /* my_osmaperr */

struct thread_start_parameter {
  my_start_routine func;
  void *arg;
};

static unsigned int __stdcall win_thread_start(void *p) {
  struct thread_start_parameter *par = (struct thread_start_parameter *)p;
  my_start_routine func = par->func;
  void *arg = par->arg;
  free(p);
  (*func)(arg);
  return 0;
}
#endif

int my_thread_create(my_thread_handle *thread, const my_thread_attr_t *attr,
                     my_start_routine func, void *arg) {
#ifndef _WIN32
  return pthread_create(&thread->thread, attr, func, arg);
#else
  struct thread_start_parameter *par;
  unsigned int stack_size;

  par = (struct thread_start_parameter *)malloc(sizeof(*par));
  if (!par) goto error_return;

  par->func = func;
  par->arg = arg;
  stack_size = attr ? attr->dwStackSize : 0;

  thread->handle =
      (HANDLE)_beginthreadex(NULL, stack_size, win_thread_start, par, 0,
                             (unsigned int *)&thread->thread);

  if (thread->handle) {
    /* Note that JOINABLE is default, so attr == NULL => JOINABLE. */
    if (attr && attr->detachstate == MY_THREAD_CREATE_DETACHED) {
      /*
        Close handles for detached threads right away to avoid leaking
        handles. For joinable threads we need the handle during
        my_thread_join. It will be closed there.
      */
      CloseHandle(thread->handle);
      thread->handle = NULL;
    }
    return 0;
  }

  my_osmaperr(GetLastError());
  free(par);

error_return:
  thread->thread = 0;
  thread->handle = NULL;
  return 1;
#endif
}

int my_thread_join(my_thread_handle *thread, void **value_ptr) {
#ifndef _WIN32
  return pthread_join(thread->thread, value_ptr);
#else
  DWORD ret;
  int result = 0;
  ret = WaitForSingleObject(thread->handle, INFINITE);
  if (ret != WAIT_OBJECT_0) {
    my_osmaperr(GetLastError());
    result = 1;
  }
  if (thread->handle) CloseHandle(thread->handle);
  thread->thread = 0;
  thread->handle = NULL;
  return result;
#endif
}

int my_thread_cancel(my_thread_handle *thread) {
#ifndef _WIN32
  return pthread_cancel(thread->thread);
#else
  bool ok = false;

  if (thread->handle) {
    ok = TerminateThread(thread->handle, 0);
    CloseHandle(thread->handle);
  }
  if (ok) return 0;

  errno = EINVAL;
  return -1;
#endif
}

void my_thread_exit(void *value_ptr) {
#ifndef _WIN32
  pthread_exit(value_ptr);
#else
  _endthreadex(0);
#endif
}

/**
  Maximum name length used for my_thread_self_setname(),
  including the terminating NUL character.
  Linux pthread_setname_np(3) is restricted to 15+1 chars,
  so we use the same limit on all platforms.
*/
#define SETNAME_MAX_LENGTH 16

void my_thread_self_setname(const char *name MY_ATTRIBUTE((unused))) {
#ifdef HAVE_PTHREAD_SETNAME_NP_LINUX
  /*
    GNU extension, see pthread_setname_np(3)
  */
  char truncated_name[SETNAME_MAX_LENGTH];
  strncpy(truncated_name, name, sizeof(truncated_name) - 1);
  truncated_name[sizeof(truncated_name) - 1] = '\0';
  pthread_setname_np(pthread_self(), truncated_name);
#else
#ifdef HAVE_PTHREAD_SETNAME_NP_MACOS
  pthread_setname_np(name);
#else
#if HAVE_SET_THREAD_DESCRIPTION
  /* Windows 10. */
  wchar_t w_name[SETNAME_MAX_LENGTH];
  int size;

  size = MultiByteToWideChar(CP_UTF8, 0, name, -1, w_name, SETNAME_MAX_LENGTH);
  if (size <= 0 || size > SETNAME_MAX_LENGTH) {
    return;
  }
  /* Make sure w_name is NUL terminated when truncated. */
  w_name[SETNAME_MAX_LENGTH - 1] = 0;
  SetThreadDescription(GetCurrentThread(), w_name);
#else
  /* Do nothing for this platform. */
  return;
#endif /* HAVE_SET_THREAD_DESCRIPTION */
#endif /* HAVE_PTHREAD_SETNAME_NP_MACOS */
#endif /* HAVE_PTHREAD_SETNAME_NP_LINUX */
}
