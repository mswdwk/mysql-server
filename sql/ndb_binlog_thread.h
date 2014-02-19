/*
   Copyright (c) 2014, Oracle and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA
*/

#ifndef NDB_BINLOG_THREAD_H
#define NDB_BINLOG_THREAD_H

#include "ndb_component.h"

class Ndb_binlog_thread : public Ndb_component
{
public:
  Ndb_binlog_thread();
  virtual ~Ndb_binlog_thread();

  /*
    Flag showing if the ndb injector thread is running, if so == 1
    -1 if it was started but later stopped for some reason
     0 if never started
  */
  int running;

private:
  virtual int do_init() { return 0;}
  virtual void do_run();
  virtual int do_deinit() { return 0;}
};

#endif
