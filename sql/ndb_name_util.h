/*
   Copyright (c) 2015, 2017, Oracle and/or its affiliates. All rights reserved.

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

#ifndef NDB_NAME_UTIL_H
#define NDB_NAME_UTIL_H


void ndb_set_dbname(const char *pathname, char *dbname);
void ndb_set_tabname(const char *pathname, char *tabname);

/*
  Return true if name starts with the prefix used for temporary name
  (normally this is "#sql")
*/
bool ndb_name_is_temp(const char* name);

/*
  Return true if name starts with the prefix used for NDB blob
  tables.

  NOTE! Those tables are internal but still returned in the public
  parts of NdbApi so they may need to be filtered in various places.
*/
bool ndb_name_is_blob_prefix(const char* name);

#endif
