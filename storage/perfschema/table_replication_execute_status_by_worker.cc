/*
      Copyright (c) 2000, 2013, Oracle and/or its affiliates. All rights reserved.

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

/**
  @file storage/perfschema/table_replication_execute_status_by_worker.cc
  Table replication_execute_status_by_worker (implementation).
*/

#include "sql_priv.h"
#include "table_replication_execute_status_by_worker.h"
#include "pfs_instr_class.h"
#include "pfs_instr.h"
#include "rpl_slave.h"
#include "rpl_info.h"
#include  "rpl_rli.h"
#include "rpl_mi.h"
#include "sql_parse.h"
#include "rpl_rli_pdb.h"

THR_LOCK table_replication_execute_status_by_worker::m_table_lock;

/* numbers in varchar count utf8 characters. */
static const TABLE_FIELD_TYPE field_types[]=
{
  {
    {C_STRING_WITH_LEN("Worker_Id")},
    {C_STRING_WITH_LEN("bigint")},
    {NULL, 0}
  },
  {
    {C_STRING_WITH_LEN("Thread_Id")},
    {C_STRING_WITH_LEN("bigint")},
    {NULL, 0}
  },
  {
    {C_STRING_WITH_LEN("Service_State")},
    {C_STRING_WITH_LEN("enum('On','Off')")},
    {NULL, 0}
  },
  {
    {C_STRING_WITH_LEN("Last_Seen_Transaction")},
    {C_STRING_WITH_LEN("char(57)")},
    {NULL, 0}
  },
  {
    {C_STRING_WITH_LEN("Last_Error_Number")},
    {C_STRING_WITH_LEN("int(11)")},
    {NULL, 0}
  },
  {
    {C_STRING_WITH_LEN("Last_Error_Message")},
    {C_STRING_WITH_LEN("varchar(1024)")},
    {NULL, 0}
  },
  {
    {C_STRING_WITH_LEN("Last_Error_Timestamp")},
    {C_STRING_WITH_LEN("timestamp")},
    {NULL, 0}
  },
};

TABLE_FIELD_DEF
table_replication_execute_status_by_worker::m_field_def=
{ 7, field_types };

PFS_engine_table_share
table_replication_execute_status_by_worker::m_share=
{
  { C_STRING_WITH_LEN("replication_execute_status_by_worker") },
  &pfs_readonly_acl,
  &table_replication_execute_status_by_worker::create,
  NULL, /* write_row */
  NULL, /* delete_all_rows */
  table_replication_execute_status_by_worker::get_row_count,
  1000, /*records- used by optimizer*/
  sizeof(PFS_simple_index), /* ref length */
  &m_table_lock,
  &m_field_def,
  false /* checked */
};

PFS_engine_table* table_replication_execute_status_by_worker::create(void)
{
  return new table_replication_execute_status_by_worker();
}

table_replication_execute_status_by_worker
  ::table_replication_execute_status_by_worker()
  : PFS_engine_table(&m_share, &m_pos),
    m_row_exists(false), m_pos(0), m_next_pos(0)
{}

table_replication_execute_status_by_worker
  ::~table_replication_execute_status_by_worker()
{}

void table_replication_execute_status_by_worker::reset_position(void)
{
  m_pos.m_index= 0;
  m_next_pos.m_index= 0;
}

int table_replication_execute_status_by_worker::rnd_next(void)
{
  Slave_worker *worker;

  mysql_mutex_lock(&LOCK_active_mi);
  Master_info *mi= active_mi;
  mysql_mutex_unlock(&LOCK_active_mi);

  if (mi->host[0])
  {
    for (m_pos.set_at(&m_next_pos);
         m_pos.m_index < active_mi->rli->workers.elements; m_pos.next())
    {
      get_dynamic(&active_mi->rli->workers, (uchar *) &worker, m_pos.m_index);
      make_row(worker);
      m_next_pos.set_after(&m_pos);
      return 0;
    }
  }
  return HA_ERR_END_OF_FILE;
}

ha_rows table_replication_execute_status_by_worker::get_row_count()
{
  mysql_mutex_lock(&LOCK_active_mi);
  uint row_count= active_mi->rli->workers.elements;
  mysql_mutex_unlock(&LOCK_active_mi);
  return row_count;
}

int table_replication_execute_status_by_worker::rnd_pos(const void *pos)
{
  Slave_worker *worker;
  set_position(pos);

  if (m_pos.m_index >= m_share.get_row_count())
    return HA_ERR_END_OF_FILE;

  mysql_mutex_lock(&LOCK_active_mi);
  get_dynamic(&active_mi->rli->workers, (uchar *) &worker, m_pos.m_index);
  mysql_mutex_unlock(&LOCK_active_mi);
  make_row(worker);
  return 0;
}

void table_replication_execute_status_by_worker::make_row(Slave_worker *w)
{
  m_row_exists= false;

  m_row.Worker_Id= w->id;
  /** Since the thread_id field is declared as char array to accomodate "NULL",
      need to convert the integer value for Thread_Idto a string.
  */
  m_row.Thread_Id= 0;
  mysql_mutex_lock(&w->jobs_lock);
  if (w->running_status == Slave_worker::RUNNING)
  {
    m_row.Thread_Id= (ulonglong)w->info_thd->thread_id;
    m_row.Thread_Id_is_null= false;
  }
  else
    m_row.Thread_Id_is_null= true;

  //TODO: Consider introducing Service_State= idle.
  if (w->running_status == Slave_worker::RUNNING)
    m_row.Service_State= PS_RPL_YES;
  else
    m_row.Service_State= PS_RPL_NO;

  m_row.Last_Error_Number= (unsigned int) w->last_error().number;

  if (gtid_mode == 0) /* gtid-mode == OFF*/
  {
    m_row.Last_Seen_Transaction_length= strlen("ANONYMOUS");
    memcpy(m_row.Last_Seen_Transaction, "ANONYMOUS",
           m_row.Last_Seen_Transaction_length);
  }
  else if (w->currently_executing_gtid.sidno)
  {
    global_sid_lock->rdlock();
    m_row.Last_Seen_Transaction_length=
    w->currently_executing_gtid.to_string(global_sid_map,
                                          m_row.Last_Seen_Transaction);
    global_sid_lock->unlock();
  }

  m_row.Last_Error_Number= (unsigned int) w->last_error().number;
  m_row.Last_Error_Message_length= 0;
  m_row.Last_Error_Timestamp= 0;

  /** If error, set error message and timestamp */
  if (m_row.Last_Error_Number)
  {
    char * temp_store= (char*)w->last_error().message;
    m_row.Last_Error_Message_length= strlen(temp_store);
    memcpy(m_row.Last_Error_Message, w->last_error().message,
           m_row.Last_Error_Message_length);

    /** time in millisecond since epoch */
    m_row.Last_Error_Timestamp= w->last_error().skr*1000000;
  }
  mysql_mutex_unlock(&w->jobs_lock);

  m_row_exists= true;
}

int table_replication_execute_status_by_worker
  ::read_row_values(TABLE *table, unsigned char *buf,  Field **fields,
                    bool read_all)
{
  Field *f;

  if (unlikely(! m_row_exists))
    return HA_ERR_RECORD_DELETED;

  DBUG_ASSERT(table->s->null_bytes == 1);
  buf[0]= 0;

  for (; (f= *fields) ; fields++)
  {
    if (read_all || bitmap_is_set(table->read_set, f->field_index))
    {
      switch(f->field_index)
      {
      case 0: /*Worker_Id*/
        set_field_ulonglong(f, m_row.Worker_Id);
        break;
      case 1: /*Thread_Id*/
        if(m_row.Thread_Id_is_null)
          f->set_null();
        else
          set_field_ulonglong(f, m_row.Thread_Id);
        break;
      case 2: /*Service_State*/
        set_field_enum(f, m_row.Service_State);
        break;
      case 3: /*Last_Seen_Transaction*/
        set_field_char_utf8(f, m_row.Last_Seen_Transaction, m_row.Last_Seen_Transaction_length);
        break;
      case 4: /*Last_Error_Number*/
        set_field_ulong(f, m_row.Last_Error_Number);
        break;
      case 5: /*Last_Error_Message*/
        set_field_varchar_utf8(f, m_row.Last_Error_Message, m_row.Last_Error_Message_length);
        break;
      case 6: /*Last_Error_Timestamp*/
        set_field_timestamp(f, m_row.Last_Error_Timestamp);
        break;
      default:
        DBUG_ASSERT(false);
      }
    }
  }
  return 0;
}
