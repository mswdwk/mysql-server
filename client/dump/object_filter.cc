/*
  Copyright (c) 2015, Oracle and/or its affiliates. All rights reserved.

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

#include "object_filter.h"
#include "pattern_matcher.h"
#include "database.h"
#include "event_scheduler_event.h"
#include "table.h"
#include "stored_procedure.h"
#include "mysql_function.h"
#include "trigger.h"
#include "privilege.h"
#include <boost/algorithm/string.hpp>

using namespace Mysql::Tools::Dump;

void Object_filter::process_object_inclusion_string(
  std::vector<std::pair<std::string, std::string> >& list,
  bool allow_schema/*= true*/,
  bool is_user_object)
{
  std::vector<std::string> objects_list;
  boost::split(objects_list, m_include_tmp_string.value(),
    boost::is_any_of(","), boost::token_compress_on);

  for (std::vector<std::string>::iterator it= objects_list.begin();
    it != objects_list.end(); ++it)
  {
    std::vector<std::string> object_parts;
    if (is_user_object)
    {
      boost::split(object_parts, *it,
        boost::is_any_of("@"), boost::token_compress_on);

      object_parts[0] = ("'" + object_parts[0] + "'");
      if (object_parts.size() == 2)
        object_parts[1] = ("'" + object_parts[1] + "'");
    }
    else
    {
      boost::split(object_parts, *it,
        boost::is_any_of("."), boost::token_compress_on);
    }
    if (object_parts.size() == 1)
    {
      if (is_user_object)
        list.push_back(std::make_pair(object_parts[0], "%"));
      else
        list.push_back(std::make_pair("%", object_parts[0]));
    }
    else if (object_parts.size() == 2 && (allow_schema || is_user_object))
    {
      list.push_back(std::make_pair(object_parts[0], object_parts[1]));
    }
    else
      m_program->error(
      Mysql::Tools::Base::Message_data(1,
      "Invalid object name specified to --include-<type> or "
      "--exclude-<type> option: \"" + *it + "\".",
      Mysql::Tools::Base::Message_type_error));
  }
}

void Object_filter::exclude_events_callback(char*)
{
  this->process_object_inclusion_string(m_events_excluded, false);
}

void Object_filter::include_events_callback(char*)
{
  this->process_object_inclusion_string(m_events_included, false);
}

void Object_filter::exclude_triggers_callback(char*)
{
  this->process_object_inclusion_string(m_triggers_excluded);
}

void Object_filter::include_triggers_callback(char*)
{
  this->process_object_inclusion_string(m_triggers_included);
}

void Object_filter::exclude_routines_callback(char*)
{
  this->process_object_inclusion_string(m_routines_excluded);
}

void Object_filter::include_routines_callback(char*)
{
  this->process_object_inclusion_string(m_routines_included);
}

void Object_filter::exclude_tables_callback(char*)
{
  this->process_object_inclusion_string(m_tables_excluded);
}

void Object_filter::include_tables_callback(char*)
{
  this->process_object_inclusion_string(m_tables_included);
}

void Object_filter::exclude_databases_callback(char*)
{
  this->process_object_inclusion_string(m_databases_excluded, false);
}

void Object_filter::include_databases_callback(char*)
{
  this->process_object_inclusion_string(m_databases_included, false);
}

void Object_filter::include_users_callback(char*)
{
  this->process_object_inclusion_string(m_users_included, false, true);
}

void Object_filter::exclude_users_callback(char*)
{
  this->process_object_inclusion_string(m_users_excluded, false, true);
}

bool Object_filter::is_user_included_by_lists(
  const std::string& user_name,
  std::vector<std::pair<std::string, std::string> >* include_list,
  std::vector<std::pair<std::string, std::string> >* exclude_list)
{
  std::vector<std::string> user_host;
  boost::split(user_host, user_name,
        boost::is_any_of("@"), boost::token_compress_on);
  return is_object_included_by_lists(user_host[0],
          user_host[1], include_list, exclude_list);
}

bool Object_filter::is_object_included_by_lists(
  const std::string& schema_name, const std::string& object_name,
  std::vector<std::pair<std::string, std::string> >* include_list,
  std::vector<std::pair<std::string, std::string> >* exclude_list)
{
  using Detail::Pattern_matcher;

  if (include_list->size() == 0 && exclude_list->size() == 0)
    return true;

  bool is_included= false;
  bool is_excluded= false;

  if (m_databases_included.size() == 0 && m_databases_excluded.size() == 0)
    return true;

  for (std::vector<std::pair<std::string, std::string> >::iterator it=
    include_list->begin(); it != include_list->end(); ++it)
    is_included|= Pattern_matcher::is_pattern_matched(schema_name, it->first)
    && Pattern_matcher::is_pattern_matched(object_name, it->second);
  for (std::vector<std::pair<std::string, std::string> >::iterator it=
    exclude_list->begin(); it != exclude_list->end(); ++it)
    is_excluded|= Pattern_matcher::is_pattern_matched(schema_name, it->first)
    && Pattern_matcher::is_pattern_matched(object_name, it->second);

  return (exclude_list->size() > 0)
    ? (!is_excluded || (is_included && is_excluded)) : is_included;
}

bool Object_filter::is_object_included_in_dump(Abstract_data_object* object)
{
  if (object == NULL)
    return true;
  if (dynamic_cast<Database*>(object) == NULL
      && dynamic_cast<Privilege*>(object) == NULL)
  {
    /*
      All objects except database/event/users need to check for schema
      inclusion rules.
      */
    if (object->get_schema().size() > 0
      && !is_object_included_by_lists("", object->get_schema(),
      &m_databases_included, &m_databases_excluded))
      return false;
  }
  std::vector<std::pair<std::string, std::string> >* include_list;
  std::vector<std::pair<std::string, std::string> >* exclude_list;
  bool* dump_switch= NULL;

  if (dynamic_cast<Table*>(object) != NULL)
  {
    include_list= &m_tables_included;
    exclude_list= &m_tables_excluded;
  }
  else if (dynamic_cast<Database*>(object) != NULL)
  {
    include_list= &m_databases_included;
    exclude_list= &m_databases_excluded;
  }
  else if (dynamic_cast<Stored_procedure*>(object) != NULL
    || dynamic_cast<Mysql_function*>(object) != NULL)
  {
    include_list= &m_routines_included;
    exclude_list= &m_routines_excluded;
    dump_switch= &m_dump_routines;
  }
  else if (dynamic_cast<Trigger*>(object) != NULL)
  {
    /*
      Check if table on which this trigger is defined is in
      excluded list
    */
    Trigger* tmp_trigger= dynamic_cast<Trigger*>(object);
    const Table *defined_table= tmp_trigger->get_defined_table();
    if (defined_table)
    {
      include_list= &m_tables_included;
      exclude_list= &m_tables_excluded;
      if (!is_object_included_by_lists(defined_table->get_schema(),
          defined_table->get_name(), include_list, exclude_list))
        return false;
    }
    include_list= &m_triggers_included;
    exclude_list= &m_triggers_excluded;
    dump_switch= &m_dump_triggers;
  }
  else if (dynamic_cast<Event_scheduler_event*>(object) != NULL)
  {
    include_list= &m_events_included;
    exclude_list= &m_events_excluded;
    dump_switch= &m_dump_events;
  }
  else if (dynamic_cast<Privilege*>(object) != NULL)
  {
    if (m_dump_users ||
        m_users_included.size() > 0 ||
        m_users_excluded.size() > 0)
    {
      include_list= &m_users_included;
      exclude_list= &m_users_excluded;
      return is_user_included_by_lists(object->get_name(),
               include_list, exclude_list);
    }
    return false;
  }
  else
    return true;

  return (dump_switch == NULL || *dump_switch)
    && is_object_included_by_lists(object->get_schema(),
    object->get_name(), include_list, exclude_list);
}

void Object_filter::create_options()
{
  this->create_new_option(&m_include_tmp_string, "include-databases",
    "Specifies comma-separated list of databases and all of its objects to "
    "include. If there is no exclusions then only included objects will be "
    "dumped. Otherwise all objects that are not on exclusion lists or are "
    "on inclusion list will be dumped.")
    ->add_callback(new Mysql::Instance_callback
    <void, char*, Object_filter>(this,
    &Object_filter::include_databases_callback));
  this->create_new_option(&m_include_tmp_string, "exclude-databases",
    "Specifies comma-separated list of databases to exclude.")
    ->add_callback(new Mysql::Instance_callback
    <void, char*, Object_filter>(this,
    &Object_filter::exclude_databases_callback));
  this->create_new_option(&m_include_tmp_string, "include-tables",
    "Specifies comma-separated list of tables to "
    "include. If there is no exclusions then only included objects will be "
    "dumped. Otherwise all objects that are not on exclusion lists or are "
    "on inclusion list will be dumped.")
    ->add_callback(new Mysql::Instance_callback
    <void, char*, Object_filter>(this,
    &Object_filter::include_tables_callback));
  this->create_new_option(&m_include_tmp_string, "exclude-tables",
    "Specifies comma-separated list of tables to exclude.")
    ->add_callback(new Mysql::Instance_callback
    <void, char*, Object_filter>(this,
    &Object_filter::exclude_tables_callback));
  this->create_new_option(&m_include_tmp_string, "include-routines",
    "Specifies comma-separated list of stored procedures or functions to "
    "include. If there is no exclusions then only included objects will be "
    "dumped. Otherwise all objects that are not on exclusion lists or are "
    "on inclusion list will be dumped.")
    ->add_callback(new Mysql::Instance_callback
    <void, char*, Object_filter>(this,
    &Object_filter::include_routines_callback));
  this->create_new_option(&m_include_tmp_string, "exclude-routines",
    "Specifies comma-separated list of stored procedures or functions to "
    "exclude.")
    ->add_callback(new Mysql::Instance_callback
    <void, char*, Object_filter>(this,
    &Object_filter::exclude_routines_callback));
  this->create_new_option(&m_include_tmp_string, "include-triggers",
    "Specifies comma-separated list of triggers to "
    "include. If there is no exclusions then only included objects will be "
    "dumped. Otherwise all objects that are not on exclusion lists or are "
    "on inclusion list will be dumped.")
    ->add_callback(new Mysql::Instance_callback
    <void, char*, Object_filter>(this,
    &Object_filter::include_triggers_callback));
  this->create_new_option(&m_include_tmp_string, "exclude-triggers",
    "Specifies comma-separated list of triggers to exclude.")
    ->add_callback(new Mysql::Instance_callback
    <void, char*, Object_filter>(this,
    &Object_filter::exclude_triggers_callback));
  this->create_new_option(&m_include_tmp_string, "include-events",
    "Specifies comma-separated list of events to "
    "include. If there is no exclusions then only included objects will be "
    "dumped. Otherwise all objects that are not on exclusion lists or are "
    "on inclusion list will be dumped.")
    ->add_callback(new Mysql::Instance_callback
    <void, char*, Object_filter>(this,
    &Object_filter::include_events_callback));
  this->create_new_option(&m_include_tmp_string, "exclude-events",
    "Specifies comma-separated list of events to exclude.")
    ->add_callback(new Mysql::Instance_callback
    <void, char*, Object_filter>(this,
    &Object_filter::exclude_events_callback));
  this->create_new_option(&m_dump_routines, "routines",
    "Dump stored procedures and functions.")
    ->set_value(true);
  this->create_new_option(&m_dump_triggers, "triggers",
    "Dump triggers.")
    ->set_value(true);
  this->create_new_option(&m_dump_events, "events",
    "Dump event scheduler events.")
    ->set_value(true);
  this->create_new_option(&m_dump_users, "users",
    "Dump users with their privileges in GRANT format. Disabled by default.")
    ->set_value(false);
  this->create_new_option(&m_include_tmp_string, "include-users",
    "Specifies comma-separated list of users to "
    "include. If there is no exclusions then only included objects will be "
    "dumped. Otherwise all objects that are not on exclusion lists or are "
    "on inclusion list will be dumped.")
    ->add_callback(new Mysql::Instance_callback
    <void, char*, Object_filter>(this,
    &Object_filter::include_users_callback));
  this->create_new_option(&m_include_tmp_string, "exclude-users",
    "Specifies comma-separated list of users to exclude. ")
    ->add_callback(new Mysql::Instance_callback
    <void, char*, Object_filter>(this,
    &Object_filter::exclude_users_callback));
}

Object_filter::Object_filter(Mysql::Tools::Base::Abstract_program* program)
  : m_program(program)
{}
