/* Copyright (c) 2015, 2017, Oracle and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA */

#include <mysql/plugin.h>
#include <mysql_version.h>
#include <stddef.h>

#include "m_string.h"                           // strlen
#include "my_dbug.h"
//#include <my_dir.h>
#include "my_sys.h"                             // my_write, my_malloc
#include "sql_plugin.h"                         // st_plugin_int

/*
  Initialize the test services at server start or plugin installation.

  SYNOPSIS
    test_services_plugin_init()

  DESCRIPTION
    Starts up heartbeatbeat thread

  RETURN VALUE
    0                    success
    1                    failure (cannot happen)
*/

static int test_services_plugin_init(void*)
{
  DBUG_ENTER("test_services_plugin_init");
  DBUG_RETURN(0);
}


/*
  Terminate the test services at server shutdown or plugin deinstallation.

  SYNOPSIS
    test_services_plugin_deinit()
    Does nothing.

  RETURN VALUE
    0                    success
    1                    failure (cannot happen)

*/

static int test_services_plugin_deinit(void*)
{
  DBUG_ENTER("test_services_plugin_deinit");
  DBUG_RETURN(0);
}


struct st_mysql_daemon test_services_plugin=
{ MYSQL_DAEMON_INTERFACE_VERSION  };

/*
  Plugin library descriptor
*/

mysql_declare_plugin(test_daemon)
{
  MYSQL_DAEMON_PLUGIN,
  &test_services_plugin,
  "test_framework",
  "Horst Hunger",
  "Test framework",
  PLUGIN_LICENSE_GPL,
  test_services_plugin_init, /* Plugin Init */
  NULL, /* Plugin Check uninstall */
  test_services_plugin_deinit, /* Plugin Deinit */
  0x0100 /* 1.0 */,
  NULL,                       /* status variables                */
  NULL,                       /* system variables                */
  NULL,                       /* config options                  */
  0,                          /* flags                           */
}
mysql_declare_plugin_end;
