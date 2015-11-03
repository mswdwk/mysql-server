/* Copyright (c) 2014, 2015, Oracle and/or its affiliates. All rights reserved.

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

#ifndef DD__OBJECT_TABLE_DEFINITION_INCLUDED
#define DD__OBJECT_TABLE_DEFINITION_INCLUDED

#include "my_global.h"

#include <vector>
#include <string>

namespace dd {

///////////////////////////////////////////////////////////////////////////

class Table;

///////////////////////////////////////////////////////////////////////////


/**
  The purpose of this interface is to enable retrieving the SQL statements
  necessary to create and populate a DD table. An Object_table instance
  may use one or more instances implementing this interface to keep track
  of the table definitions corresponding to the supported DD versions.

  This interface also enables storing (in main memory) and retrieving the
  meta data associated with the table definition.
*/

class Object_table_definition
{
public:
  virtual ~Object_table_definition()
  { };

  /**
    Get the SQL DDL statement for creating the dictionary table.

    @return String containing the SQL DDL statement for the target table.
   */
  virtual std::string build_ddl_create_table() const= 0;

  /**
    Get the SQL DDL statement for adding foreign keys for the table.

    @return String containing the SQL DDL statement for adding foreign keys.
   */
  virtual std::string build_ddl_add_cyclic_foreign_keys() const= 0;

  /**
    Get the SQL DML statements for populating the table.

    @return Vector of strings containing SQL DML statements
   */
  virtual const std::vector<std::string> &dml_populate_statements() const= 0;

  /**
    Set generated meta data representing the object table.

    @param table Object structure representing the meta data corresponding
                 to the table definition
  */
  virtual void meta_data(Table *table)= 0;

  /**
    Get meta data representing the object table.

    @return Object structure representing the meta data corresponding
            to the table definition
  */
  virtual Table *meta_data() const= 0;
};

///////////////////////////////////////////////////////////////////////////

}

#endif	// DD__OBJECT_TABLE_DEFINITION_INCLUDED

