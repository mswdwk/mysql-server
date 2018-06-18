#ifndef PFS_BATCH_MODE_INCLUDED
#define PFS_BATCH_MODE_INCLUDED

/* Copyright (c) 2018, Oracle and/or its affiliates. All rights reserved.

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

#include "sql/sql_optimizer.h"

// A RAII class to handle (optionally) turning on batch mode in front of
// scanning a row iterator, and then turn it back off afterwards (on
// destruction).
class PFSBatchMode {
 public:
  // qep_tab should be the table we're scanning.
  PFSBatchMode(QEP_TAB *qep_tab) : m_qep_tab(qep_tab) {
    if (qep_tab->join() == nullptr) {
      // The QEP_TAB isn't even part of a join (typically used when sorting
      // data for UPDATE or DELETE), so we can safely enable batch mode.
      m_enable = true;
    } else {
      // If this table is a single-table right-hand side of an outer join
      // (which is what the last_inner() test checks for), NestedLoopIterator
      // will enable PFS batch mode for us, so do not check it here.
      m_enable = qep_tab->pfs_batch_update(qep_tab->join()) &&
                 qep_tab->last_inner() == NO_PLAN_IDX;
    }
    if (m_enable) {
      qep_tab->table()->file->start_psi_batch_mode();
    }
  }

  ~PFSBatchMode() {
    if (m_enable) {
      m_qep_tab->table()->file->end_psi_batch_mode();
    }
  }

 private:
  bool m_enable;
  QEP_TAB *m_qep_tab;
};

#endif /* PFS_BATCH_MODE_INCLUDED */
