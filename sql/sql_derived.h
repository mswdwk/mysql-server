/* Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.

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

#ifndef SQL_DERIVED_INCLUDED
#define SQL_DERIVED_INCLUDED

struct TABLE_LIST;
class THD;
struct LEX;

bool mysql_handle_derived(LEX *lex, bool (*processor)(THD *thd,
                                                      LEX *lex,
                                                      TABLE_LIST *table));
bool mysql_derived_prepare(THD *thd, LEX *lex, TABLE_LIST *t);
bool mysql_derived_optimize(THD *thd, LEX *lex, TABLE_LIST *t);
bool mysql_derived_create(THD *thd, LEX *lex, TABLE_LIST *t);
bool mysql_derived_materialize(THD *thd, LEX *lex, TABLE_LIST *t);
bool
mysql_handle_single_derived(LEX *lex, TABLE_LIST *derived,
                            bool (*processor)(THD*, LEX*, TABLE_LIST*));
#endif /* SQL_DERIVED_INCLUDED */
