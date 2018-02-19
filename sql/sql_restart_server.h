/* Copyright (c) 2017, Oracle and/or its affiliates. All rights reserved.

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License, version 2.0,
  as published by the Free Software Foundation.

  This program is also distributed with certain software (including
  but not limited to OpenSSL) that is licensed under separate terms,
  as designated in a particular file or component or in included license
  documentation.  The authors of MySQL hereby grant you an additional
  permission to link the program and your derivative works with the
  separately licensed software that they have included with MySQL.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License, version 2.0, for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

#ifndef SQL_RESTART_SERVER_H_
#define SQL_RESTART_SERVER_H_

#include "sql/sql_cmd.h"  // Sql_cmd

#ifndef _WIN32
/**
  Check if mysqld is managed by an external supervisor.

  @return true if it is under control of supervisor else false.
*/

bool is_mysqld_managed();
#endif  // _WIN32

/**
  Sql_cmd_restart_server represents the RESTART server statement.
*/

class Sql_cmd_restart_server : public Sql_cmd {
 public:
  bool execute(THD *thd) override;
  enum_sql_command sql_command_code() const override {
    return SQLCOM_RESTART_SERVER;
  }
};

#endif  // SQL_RESTART_SERVER_H_
