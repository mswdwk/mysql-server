/* Copyright (c) 2012, 2017, Oracle and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; version 2 of the
   License.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
   02110-1301 USA */

#include <string.h>

#include "m_ctype.h"
#include "my_dbug.h"
#include "sql/rpl_gtid.h"


//const int Gtid_specification::MAX_TEXT_LENGTH;

#ifdef MYSQL_SERVER

enum_return_status Gtid_specification::parse(Sid_map *sid_map, const char *text)
{
  DBUG_ENTER("Gtid_specification::parse");
  DBUG_ASSERT(text != NULL);
  if (my_strcasecmp(&my_charset_latin1, text, "AUTOMATIC") == 0)
  {
    type= AUTOMATIC_GTID;
    gtid.sidno= 0;
    gtid.gno= 0;
  }
  else if (my_strcasecmp(&my_charset_latin1, text, "ANONYMOUS") == 0)
  {
    type= ANONYMOUS_GTID;
    gtid.sidno= 0;
    gtid.gno= 0;
  }
  else
  {
    PROPAGATE_REPORTED_ERROR(gtid.parse(sid_map, text));
    type= ASSIGNED_GTID;
  }
  RETURN_OK;
}


bool Gtid_specification::is_valid(const char *text)
{
  DBUG_ENTER("Gtid_specification::is_valid");
  DBUG_ASSERT(text != NULL);
  if (my_strcasecmp(&my_charset_latin1, text, "AUTOMATIC") == 0)
    DBUG_RETURN(true);
  else if (my_strcasecmp(&my_charset_latin1, text, "ANONYMOUS") == 0)
    DBUG_RETURN(true);
  else
    DBUG_RETURN(Gtid::is_valid(text));
}

#endif // ifdef MYSQL_SERVER


int Gtid_specification::to_string(const rpl_sid *sid, char *buf) const
{
  DBUG_ENTER("Gtid_specification::to_string(char*)");
  switch (type)
  {
  case AUTOMATIC_GTID:
    strcpy(buf, "AUTOMATIC");
    DBUG_RETURN(9);
  case NOT_YET_DETERMINED_GTID:
    /*
      This can happen if user issues SELECT @@SESSION.GTID_NEXT
      immediately after a BINLOG statement containing a
      Format_description_log_event.
    */
    strcpy(buf, "NOT_YET_DETERMINED");
    DBUG_RETURN(18);
  case ANONYMOUS_GTID:
    strcpy(buf, "ANONYMOUS");
    DBUG_RETURN(9);
  /*
    UNDEFINED_GTID must be printed like ASSIGNED_GTID because of
    SELECT @@SESSION.GTID_NEXT.
  */
  case UNDEFINED_GTID:
  case ASSIGNED_GTID:
    DBUG_RETURN(gtid.to_string(*sid, buf));
  }
  DBUG_ASSERT(0);
  DBUG_RETURN(0);
}


int Gtid_specification::to_string(const Sid_map *sid_map, char *buf, bool need_lock) const
{
  return to_string(type == ASSIGNED_GTID || type == UNDEFINED_GTID ?
                   &sid_map->sidno_to_sid(gtid.sidno, need_lock) : NULL,
                   buf);
}
