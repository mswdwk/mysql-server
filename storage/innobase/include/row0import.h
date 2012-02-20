/*****************************************************************************

Copyright (c) 2012, Oracle and/or its affiliates. All Rights Reserved.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; version 2 of the License.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Suite 500, Boston, MA 02110-1335 USA

*****************************************************************************/

/**************************************************//**
@file include/row0import.h
Header file for import tablespace functions. 

Created 2012-02-08 by Sunny Bains
*******************************************************/

#ifndef row0import_h
#define row0import_h

#include "univ.i"
#include "db0err.h"

// Forward declarations
struct trx_struct;
struct dict_table_struct;
struct row_prebuilt_struct;

/*****************************************************************//**
Imports a tablespace. The space id in the .ibd file must match the space id
of the table in the data dictionary.
@return	error code or DB_SUCCESS */
UNIV_INTERN
db_err
row_import_for_mysql(
/*=================*/
	dict_table_struct*	table,		/*!< in/out: table */
	row_prebuilt_struct*	prebuilt);	/*!< in: prebuilt struct
						in MySQL */

/*****************************************************************//**
Update the DICT_TF2_DISCARDED flag in SYS_TABLES.
@return DB_SUCCESS or error code. */
UNIV_INTERN
db_err
row_import_update_discarded_flag(
/*=============================*/
	trx_struct*		trx,		/*!< in/out: transaction that
						covers the update */
	const dict_table_struct*table,		/*!< in: Table for which we want
						to set the root table->flags2 */
	bool			discarded,	/*!< in: set MIX_LEN column bit
						to discarded, if true */
	bool			dict_locked);	/*!< Set to TRUE if the 
						caller already owns the 
						dict_sys_t:: mutex. */

/*****************************************************************//**
Update the <space, root page> of a table's indexes from the values
in the data dictionary.
@return DB_SUCCESS or error code */
UNIV_INTERN
db_err
row_import_update_index_root(
/*=========================*/
	trx_struct*		trx,		/*!< in/out: transaction that
						covers the update */
	const dict_table_struct*table,		/*!< in: Table for which we want
						to set the root page_no */
	bool			reset,		/*!< if true then set to
						FIL_NUL */
	bool			dict_locked);	/*!< Set to TRUE if the 
						caller already owns the 
						dict_sys_t:: mutex. */
#ifndef UNIV_NONINL
#include "row0import.ic"
#endif

#endif /* row0import_h */
