/* Copyright (c) 2016 Oracle and/or its affiliates. All rights reserved.

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

#ifndef DD_TABLES__EVENTS_INCLUDED
#define DD_TABLES__EVENTS_INCLUDED

#include "my_global.h"

#include "dd/impl/types/dictionary_object_table_impl.h" // dd::Dictionary_obj...

namespace dd {
class Object_key;
namespace tables {

///////////////////////////////////////////////////////////////////////////

class Events : public Dictionary_object_table_impl
{
public:
  static const Events &instance()
  {
    static Events *s_instance= new Events();
    return *s_instance;
  }

  static const std::string &table_name()
  {
    static std::string s_table_name("events");
    return s_table_name;
  }

  enum enum_fields
  {
    FIELD_ID,
    FIELD_SCHEMA_ID,
    FIELD_NAME,
    FIELD_DEFINER,
    FIELD_TIME_ZONE,
    FIELD_DEFINITION,
    FIELD_DEFINITION_UTF8,
    FIELD_EXECUTE_AT,
    FIELD_INTERVAL_VALUE,
    FIELD_INTERVAL_FIELD,
    FIELD_SQL_MODE,
    FIELD_STARTS,
    FIELD_ENDS,
    FIELD_STATUS,
    FIELD_ON_COMPLETION,
    FIELD_CREATED,
    FIELD_LAST_ALTERED,
    FIELD_LAST_EXECUTED,
    FIELD_COMMENT,
    FIELD_ORIGINATOR,
    FIELD_CLIENT_COLLATION_ID,
    FIELD_CONNECTION_COLLATION_ID,
    FIELD_SCHEMA_COLLATION_ID
  };

  Events();

  virtual const std::string &name() const
  { return Events::table_name(); }

  virtual Dictionary_object *create_dictionary_object(const Raw_record &) const;

  static bool update_object_key(Item_name_key *key,
                                Object_id schema_id,
                                const std::string &event_name);

  static Object_key *create_key_by_schema_id(Object_id schema_id);
};

///////////////////////////////////////////////////////////////////////////

}
}

#endif // DD_TABLES__EVENTS_INCLUDED
