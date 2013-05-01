/*****************************************************************************

Copyright (c) 1995, 2013, Oracle and/or its affiliates. All Rights Reserved.

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
@file include/fil0fil.h
The low-level file system

Created 10/25/1995 Heikki Tuuri
*******************************************************/

#ifndef fil0fil_h
#define fil0fil_h

#include "univ.i"

#ifndef UNIV_INNOCHECKSUM

#include "dict0types.h"
#include "ut0byte.h"
#include "os0file.h"
#ifndef UNIV_HOTBACKUP
#include "sync0rw.h"
#include "ibuf0types.h"
#include "log0log.h"
#endif /* !UNIV_HOTBACKUP */

#include <list>
#include <vector>

// Forward declaration
struct trx_t;
struct fil_space_t;
struct btr_create_t;

typedef std::list<const char*> space_name_list_t;

/** When mysqld is run, the default directory "." is the mysqld datadir,
but in the MySQL Embedded Server Library and ibbackup it is not the default
directory, and we must set the base file path explicitly */
extern const char*	fil_path_to_mysql_datadir;

/** Initial size of a single-table tablespace in pages */
#define FIL_IBD_FILE_INITIAL_SIZE	4

/** 'null' (undefined) page offset in the context of file spaces */
#define	FIL_NULL	ULINT32_UNDEFINED

/* Space address data type; this is intended to be used when
addresses accurate to a byte are stored in file pages. If the page part
of the address is FIL_NULL, the address is considered undefined. */

typedef	byte	fil_faddr_t;	/*!< 'type' definition in C: an address
				stored in a file page is a string of bytes */
#define FIL_ADDR_PAGE	0	/* first in address is the page offset */
#define	FIL_ADDR_BYTE	4	/* then comes 2-byte byte offset within page*/

#define	FIL_ADDR_SIZE	6	/* address size is 6 bytes */

/** File space address */
struct fil_addr_t {
	ulint	page;		/*!< page number within a space */
	ulint	boffset;	/*!< byte offset within the page */
};

/** Cache all info needed for completing truncate of table
especially updating dictionary as it is not allowed during REDO. */
struct truncate_redo_cache_t
{
	typedef std::map<index_id_t, ulint>	index_page_cache_t;

	truncate_redo_cache_t(table_id_t old_id, table_id_t new_id)
		:
		m_old_table_id(old_id),
		m_new_table_id(new_id),
		m_new_page_no()
	{
		/* Do nothing */
	}

	/* Register new page no for given index id.
	@param index_id		index id
	@param root_page_no	new root page no */
	void register_new_page_no(index_id_t index_id, ulint root_page_no)
	{
		m_new_page_no[index_id] = root_page_no; 
	}

	/** ID of table that is being truncated. */
	table_id_t		m_old_table_id;

	/** New ID that will be assigned to table on truncation. */
	table_id_t		m_new_table_id;

	/** map of index-id to new root page no. */
	index_page_cache_t	m_new_page_no;
};

/** The information of MLOG_FILE_TRUNCATE redo record */
struct truncate_t {

	truncate_t()
		:
		m_space_id(),
		m_old_table_id(),
		m_new_table_id(),
		m_dir_path(),
		m_tablename(),
		m_tablespace_flags(),
		m_format_flags(),
		m_indexes()
	{
		/* Do nothing */
	}

	~truncate_t() {
		m_old_table_id = 0;
		m_new_table_id = 0;

		if (m_dir_path != NULL) {
			::free(m_dir_path);
			m_dir_path = 0;
		}

		if (m_tablename != NULL) {
			::free(m_tablename);
			m_tablename = 0;
		}

		m_tablespace_flags = 0;
		m_format_flags = 0;

		m_indexes.clear();
	}

	/** The index information of MLOG_FILE_TRUNCATE redo record */
	struct index_t {

		typedef std::vector<byte> fields_t;

		index_t()
			:
			m_id(),
			m_type(),
			m_root_page_no(),
			m_n_fields(),
			m_trx_id_pos(ULINT_UNDEFINED),
			m_fields()
		{
			/* Do nothing */
		}

		/**
		Set the truncate redo log values for a compressed table. */
		void set(const dict_index_t* index);

		/** Index id */
		index_id_t	m_id;

		/** Index type */
		ulint		m_type;

		/** Root Page Number */
		ulint		m_root_page_no;

		/** Number of index fields */
		ulint		m_n_fields;

		/** DATA_TRX_ID column position. */
		ulint		m_trx_id_pos;

		/** Compressed table field meta data, encode by
		page_zip_fields_encode. Empty for non-compressed tables.
		Should be NUL terminated. */
		fields_t	m_fields;
	};

	/**
	Create an index for a table.

	@param table_name	table name, for which to create the index
	@param space_id		space id where we have to create the index
	@param zip_size		page size of the .ibd file
	@param index_type	type of index to truncate
	@param index_id		id of index to truncate
	@param btr_create_info	control info for ::btr_create()
	@param mtr		mini-transaction covering the create index
	@return root page no or FIL_NULL on failure */
	ulint create_index(
		const char*	table_name,
		ulint		space_id,
		ulint		zip_size,
		ulint		index_type,
		index_id_t      index_id,
		btr_create_t&	btr_create_info,
		mtr_t*		mtr) const;

	/** Create the indexes for a table

	@param table_name	table name, for which to create the indexes
	@param space_id		space id where we have to create the indexes
	@param zip_size		page size of the .ibd file
	@param flags		tablespace flags
	@param format_flags	page format flags
	@param redo_cache_entry	cache to store info about new page no so as
	to update them in dictionary post recovery
	@return DB_SUCCESS or error code. */
	dberr_t create_indexes(
		const char*		table_name,
		ulint			space_id,
		ulint			zip_size,
		ulint			flags,
		ulint			format_flags,
		truncate_redo_cache_t* 	redo_cache_entry) const; 

	/** Drop indexes for a table.
	@param space_id		space_id where table/indexes resides.
	@return DB_SUCCESS or error code. */
	void drop_indexes(
		ulint			space_id) const;

	/**
	Parses MLOG_FILE_TRUNCATE redo record during recovery
	@param ptr		buffer containing the main body of
				MLOG_FILE_TRUNCATE record
	@param end_ptr		buffer end
	@param flags		tablespace flags

	@return true if successfully parsed the MLOG_FILE_TRUNCATE record */
	bool parse(byte** ptr, const byte** end_ptr, ulint flags);

	/**
	Write a redo log record for truncating a single-table tablespace.

	@param space_id		space id
	@param tablename	the table name in the usual
				databasename/tablename format of InnoDB
	@param flags		tablespace flags
	@param format_flags	page format */
	void write(
		ulint		space_id,
		const char*	tablename,
		ulint		flags,
		ulint		format_flags) const;

	/**
	Truncate a single-table tablespace. The tablespace must be cached
	in the memory cache.
	@param space_id			space id
	@param tablename		the table name in the usual
					databasename/tablename format of InnoDB
	@param dir_path			data directory path for .ibd file
	@param flags			tablespace flags
	@param trunc_to_default		truncate to default size if tablespace
					is being newly re-initialized.
	@return DB_SUCCESS or error */
	static dberr_t truncate(
		ulint		space_id,
		const char*	tablename,
		const char*	dir_path,
		ulint		flags,
		bool		trunc_to_default);

	typedef std::vector<index_t> indexes_t;

	/** Space ID of tablespace */
	table_id_t		m_space_id;

	/** ID of table that is being truncated. */
	table_id_t		m_old_table_id;

	/** New ID that will be assigned to table on truncation. */
	table_id_t		m_new_table_id;

	/** Data dir path of tablespace */
	char*			m_dir_path;

	/** Table name */
	char*			m_tablename;

	/** Tablespace Flags */
	ulint			m_tablespace_flags;

	/** Format flags (log flags; stored in page-no field of redo header) */
	ulint			m_format_flags;

	/** Index meta-data */
	indexes_t		m_indexes;
};

typedef std::vector<truncate_t*> truncate_tables_t;

/** The null file address */
extern fil_addr_t	fil_addr_null;

#endif /* !UNIV_INNOCHECKSUM */

/** The byte offsets on a file page for various variables @{ */
#define FIL_PAGE_SPACE_OR_CHKSUM 0	/*!< in < MySQL-4.0.14 space id the
					page belongs to (== 0) but in later
					versions the 'new' checksum of the
					page */
#define FIL_PAGE_OFFSET		4	/*!< page offset inside space */
#define FIL_PAGE_PREV		8	/*!< if there is a 'natural'
					predecessor of the page, its
					offset.  Otherwise FIL_NULL.
					This field is not set on BLOB
					pages, which are stored as a
					singly-linked list.  See also
					FIL_PAGE_NEXT. */
#define FIL_PAGE_NEXT		12	/*!< if there is a 'natural' successor
					of the page, its offset.
					Otherwise FIL_NULL.
					B-tree index pages
					(FIL_PAGE_TYPE contains FIL_PAGE_INDEX)
					on the same PAGE_LEVEL are maintained
					as a doubly linked list via
					FIL_PAGE_PREV and FIL_PAGE_NEXT
					in the collation order of the
					smallest user record on each page. */
#define FIL_PAGE_LSN		16	/*!< lsn of the end of the newest
					modification log record to the page */
#define	FIL_PAGE_TYPE		24	/*!< file page type: FIL_PAGE_INDEX,...,
					2 bytes.

					The contents of this field can only
					be trusted in the following case:
					if the page is an uncompressed
					B-tree index page, then it is
					guaranteed that the value is
					FIL_PAGE_INDEX.
					The opposite does not hold.

					In tablespaces created by
					MySQL/InnoDB 5.1.7 or later, the
					contents of this field is valid
					for all uncompressed pages. */
#define FIL_PAGE_FILE_FLUSH_LSN	26	/*!< this is only defined for the
					first page in a system tablespace
					data file (ibdata*, not *.ibd):
					the file has been flushed to disk
					at least up to this lsn */
#define FIL_PAGE_ARCH_LOG_NO_OR_SPACE_ID  34 /*!< starting from 4.1.x this
					contains the space id of the page */
#define FIL_PAGE_DATA		38	/*!< start of the data on the page */
/* @} */
/** File page trailer @{ */
#define FIL_PAGE_END_LSN_OLD_CHKSUM 8	/*!< the low 4 bytes of this are used
					to store the page checksum, the
					last 4 bytes should be identical
					to the last 4 bytes of FIL_PAGE_LSN */
#define FIL_PAGE_DATA_END	8	/*!< size of the page trailer */
/* @} */

#ifndef UNIV_INNOCHECKSUM

/** File page types (values of FIL_PAGE_TYPE) @{ */
#define FIL_PAGE_INDEX		17855	/*!< B-tree node */
#define FIL_PAGE_UNDO_LOG	2	/*!< Undo log page */
#define FIL_PAGE_INODE		3	/*!< Index node */
#define FIL_PAGE_IBUF_FREE_LIST	4	/*!< Insert buffer free list */
/* File page types introduced in MySQL/InnoDB 5.1.7 */
#define FIL_PAGE_TYPE_ALLOCATED	0	/*!< Freshly allocated page */
#define FIL_PAGE_IBUF_BITMAP	5	/*!< Insert buffer bitmap */
#define FIL_PAGE_TYPE_SYS	6	/*!< System page */
#define FIL_PAGE_TYPE_TRX_SYS	7	/*!< Transaction system data */
#define FIL_PAGE_TYPE_FSP_HDR	8	/*!< File space header */
#define FIL_PAGE_TYPE_XDES	9	/*!< Extent descriptor page */
#define FIL_PAGE_TYPE_BLOB	10	/*!< Uncompressed BLOB page */
#define FIL_PAGE_TYPE_ZBLOB	11	/*!< First compressed BLOB page */
#define FIL_PAGE_TYPE_ZBLOB2	12	/*!< Subsequent compressed BLOB page */
#define FIL_PAGE_TYPE_LAST	FIL_PAGE_TYPE_ZBLOB2
					/*!< Last page type */
/* @} */

/** Space types @{ */
#define FIL_TABLESPACE		501	/*!< tablespace */
#define FIL_LOG			502	/*!< redo log */
/* @} */

/** The number of fsyncs done to the log */
extern ulint	fil_n_log_flushes;

/** Number of pending redo log flushes */
extern ulint	fil_n_pending_log_flushes;
/** Number of pending tablespace flushes */
extern ulint	fil_n_pending_tablespace_flushes;

/** Number of files currently open */
extern ulint	fil_n_file_opened;

#ifndef UNIV_HOTBACKUP
/*******************************************************************//**
Returns the version number of a tablespace, -1 if not found.
@return version number, -1 if the tablespace does not exist in the
memory cache */
UNIV_INTERN
ib_int64_t
fil_space_get_version(
/*==================*/
	ulint	id);	/*!< in: space id */
/*******************************************************************//**
Returns the latch of a file space.
@return	latch protecting storage allocation */
UNIV_INTERN
rw_lock_t*
fil_space_get_latch(
/*================*/
	ulint	id,	/*!< in: space id */
	ulint*	zip_size);/*!< out: compressed page size, or
			0 for uncompressed tablespaces */
/*******************************************************************//**
Returns the type of a file space.
@return	FIL_TABLESPACE or FIL_LOG */
UNIV_INTERN
ulint
fil_space_get_type(
/*===============*/
	ulint	id);	/*!< in: space id */
#endif /* !UNIV_HOTBACKUP */
/*******************************************************************//**
Appends a new file to the chain of files of a space. File must be closed.
@return pointer to the file name, or NULL on error */
UNIV_INTERN
char*
fil_node_create(
/*============*/
	const char*	name,	/*!< in: file name (file must be closed) */
	ulint		size,	/*!< in: file size in database blocks, rounded
				downwards to an integer */
	ulint		id,	/*!< in: space id where to append */
	ibool		is_raw)	/*!< in: TRUE if a raw device or
				a raw disk partition */
	__attribute__((nonnull, warn_unused_result));
/*******************************************************************//**
Creates a space memory object and puts it to the 'fil system' hash table.
If there is an error, prints an error message to the .err log.
@return	TRUE if success */
UNIV_INTERN
ibool
fil_space_create(
/*=============*/
	const char*	name,	/*!< in: space name */
	ulint		id,	/*!< in: space id */
	ulint		zip_size,/*!< in: compressed page size, or
				0 for uncompressed tablespaces */
	ulint		purpose);/*!< in: FIL_TABLESPACE, or FIL_LOG if log */
/*******************************************************************//**
Assigns a new space id for a new single-table tablespace. This works simply by
incrementing the global counter. If 4 billion id's is not enough, we may need
to recycle id's.
@return	TRUE if assigned, FALSE if not */
UNIV_INTERN
ibool
fil_assign_new_space_id(
/*====================*/
	ulint*	space_id);	/*!< in/out: space id */
/*******************************************************************//**
Returns the path from the first fil_node_t found for the space ID sent.
The caller is responsible for freeing the memory allocated here for the
value returned.
@return	a copy of fil_node_t::path, NULL if space is zero or not found. */
UNIV_INTERN
char*
fil_space_get_first_path(
/*=====================*/
	ulint	id);	/*!< in: space id */
/*******************************************************************//**
Returns the size of the space in pages. The tablespace must be cached in the
memory cache.
@return	space size, 0 if space not found */
UNIV_INTERN
ulint
fil_space_get_size(
/*===============*/
	ulint	id);	/*!< in: space id */
/*******************************************************************//**
Returns the flags of the space. The tablespace must be cached
in the memory cache.
@return	flags, ULINT_UNDEFINED if space not found */
UNIV_INTERN
ulint
fil_space_get_flags(
/*================*/
	ulint	id);	/*!< in: space id */
/*******************************************************************//**
Returns the compressed page size of the space, or 0 if the space
is not compressed. The tablespace must be cached in the memory cache.
@return	compressed page size, ULINT_UNDEFINED if space not found */
UNIV_INTERN
ulint
fil_space_get_zip_size(
/*===================*/
	ulint	id);	/*!< in: space id */
/*******************************************************************//**
Checks if the pair space, page_no refers to an existing page in a tablespace
file space. The tablespace must be cached in the memory cache.
@return	TRUE if the address is meaningful */
UNIV_INTERN
ibool
fil_check_adress_in_tablespace(
/*===========================*/
	ulint	id,	/*!< in: space id */
	ulint	page_no);/*!< in: page number */
/****************************************************************//**
Initializes the tablespace memory cache. */
UNIV_INTERN
void
fil_init(
/*=====*/
	ulint	hash_size,	/*!< in: hash table size */
	ulint	max_n_open);	/*!< in: max number of open files */
/*******************************************************************//**
Initializes the tablespace memory cache. */
UNIV_INTERN
void
fil_close(void);
/*===========*/
/*******************************************************************//**
Opens all log files and system tablespace data files. They stay open until the
database server shutdown. This should be called at a server startup after the
space objects for the log and the system tablespace have been created. The
purpose of this operation is to make sure we never run out of file descriptors
if we need to read from the insert buffer or to write to the log. */
UNIV_INTERN
void
fil_open_log_and_system_tablespace_files(void);
/*==========================================*/
/*******************************************************************//**
Closes all open files. There must not be any pending i/o's or not flushed
modifications in the files. */
UNIV_INTERN
void
fil_close_all_files(void);
/*=====================*/
/*******************************************************************//**
Closes the redo log files. There must not be any pending i/o's or not
flushed modifications in the files. */
UNIV_INTERN
void
fil_close_log_files(
/*================*/
	bool	free);	/*!< in: whether to free the memory object */
/*******************************************************************//**
Sets the max tablespace id counter if the given number is bigger than the
previous value. */
UNIV_INTERN
void
fil_set_max_space_id_if_bigger(
/*===========================*/
	ulint	max_id);/*!< in: maximum known id */
#ifndef UNIV_HOTBACKUP
/****************************************************************//**
Writes the flushed lsn and the latest archived log number to the page
header of the first page of each data file in the system tablespace.
@return	DB_SUCCESS or error number */
UNIV_INTERN
dberr_t
fil_write_flushed_lsn_to_data_files(
/*================================*/
	lsn_t	lsn,		/*!< in: lsn to write */
	ulint	arch_log_no);	/*!< in: latest archived log file number */
/*******************************************************************//**
Reads the flushed lsn and tablespace flag fields from a data
file at database startup.
@retval NULL on success, or if innodb_force_recovery is set
@return pointer to an error message string */
UNIV_INTERN
const char*
fil_read_first_page(
/*================*/
	os_file_t	data_file,		/*!< in: open data file */
	bool		one_read_already,	/*!< in: true when not reading
						the first data file of a
						tablespace */
	ulint*		flags,			/*!< out: tablespace flags */
	ulint*		space_id,		/*!< out: tablespace ID */
	lsn_t*		min_flushed_lsn,	/*!< out: min of flushed
						lsn values in data files */
	lsn_t*		max_flushed_lsn)	/*!< out: max of flushed
						lsn values in data files */
	__attribute__((warn_unused_result));
/*******************************************************************//**
Increments the count of pending operation, if space is not being deleted.
@return	TRUE if being deleted, and operation should be skipped */
UNIV_INTERN
ibool
fil_inc_pending_ops(
/*================*/
	ulint	id);	/*!< in: space id */
/*******************************************************************//**
Decrements the count of pending operations. */
UNIV_INTERN
void
fil_decr_pending_ops(
/*=================*/
	ulint	id);	/*!< in: space id */
#endif /* !UNIV_HOTBACKUP */
/********************************************************//**
Creates the database directory for a table if it does not exist yet. */
UNIV_INTERN
void
fil_create_directory_for_tablename(
/*===============================*/
	const char*	name);	/*!< in: name in the standard
				'databasename/tablename' format */
/********************************************************//**
Recreates table indexes by applying
MLOG_FILE_TRUNCATE redo record during recovery. */
UNIV_INTERN
void
fil_recreate_table(
/*===============*/
	ulint			space_id,	/*!< in: space id */
	ulint			format_flags,	/*!< in: page format */
	ulint			flags,		/*!< in: tablespace flags */
	const char*		name,		/*!< in: table name */
	const truncate_t&	truncate,	/*!< in: The information of
						MLOG_FILE_TRUNCATE record */
	lsn_t			recv_lsn,	/*!< in: the end LSN of
						the log record */
	truncate_redo_cache_t*	redo_cache_entry);
						/*!< out: cache to store
						information needed for
						completion of truncate. */
/********************************************************//**
Recreates the tablespace and table indexes by applying
MLOG_FILE_TRUNCATE redo record during recovery. */
UNIV_INTERN
void
fil_recreate_tablespace(
/*====================*/
	ulint			space_id,	/*!< in: space id */
	ulint			format_flags,	/*!< in: page format */
	ulint			flags,		/*!< in: tablespace flags */
	const char*		name,		/*!< in: table name */
	const truncate_t&	truncate,	/*!< in: The information of
						MLOG_FILE_TRUNCATE record */
	lsn_t			recv_lsn,	/*!< in: the end LSN of
						the log record */
	truncate_redo_cache_t*	redo_cache_entry);
						/*!< out: cache to store
						information needed for
						completion of truncate. */
/*******************************************************************//**
Parses the body of a log record written about an .ibd file operation. That is,
the log record part after the standard (type, space id, page no) header of the
log record.

If desired, also replays the delete or rename operation if the .ibd file
exists and the space id in it matches. Replays the create operation if a file
at that path does not exist yet. If the database directory for the file to be
created does not exist, then we create the directory, too.

Note that ibbackup --apply-log sets fil_path_to_mysql_datadir to point to the
datadir that we should use in replaying the file operations.
@return end of log record, or NULL if the record was not completely
contained between ptr and end_ptr */
UNIV_INTERN
byte*
fil_op_log_parse_or_replay(
/*=======================*/
	byte*		ptr,		/*!< in/out: buffer containing the log
					record body, or an initial segment
					of it, if the record does not fire
					completely between ptr and end_ptr */
	const byte*	end_ptr,	/*!< in: buffer end */
	ulint		type,		/*!< in: the type of this log record */
	ulint		space_id,	/*!< in: the space id of the tablespace
					in question */
	ulint		log_flags,	/*!< in: redo log flags
					(stored in the page number parameter) */
	lsn_t		recv_lsn,	/*!< in: the end LSN of log record */
	bool		parse_only);	/*!< in: if true, parse the
					log record don't replay it. */
/*******************************************************************//**
Deletes a single-table tablespace. The tablespace must be cached in the
memory cache.
@return	TRUE if success */
UNIV_INTERN
dberr_t
fil_delete_tablespace(
/*==================*/
	ulint		id,		/*!< in: space id */
	buf_remove_t	buf_remove);	/*!< in: specify the action to take
					on the tables pages in the buffer
					pool */
/*******************************************************************//**
Check if an index tree is freed by a descriptor bit of a page.
@return true if the index tree is freed */
UNIV_INTERN
bool
fil_index_tree_is_freed(
/*====================*/
	ulint	space_id,	/*!< in: space id */
	ulint	root_page_no,	/*!< in: root page no of an index tree */
	ulint	zip_size);	/*!< in: compressed page size in bytes */
/*******************************************************************//**
Prepare for truncating a single-table tablespace. The tablespace
must be cached in the memory cache.
1) Check pending operations on a tablespace;
2) Remove all insert buffer entries for the tablespace;
@return DB_SUCCESS or error */
UNIV_INTERN
dberr_t
fil_prepare_for_truncate(
/*=====================*/
	ulint	id);			/*!< in: space id */
/*******************************************************************//**
The set of the truncated tablespaces need to be initialized during recovery.
@return true if the space is in the set, otherwise false */
UNIV_INTERN
bool
fil_space_is_truncated(
/*===================*/
	ulint		id);		/* !< in: space id */
/*******************************************************************//**
Reset truncated space id */
UNIV_INTERN
void
fil_space_truncated_reset();
/*========================*/
/**********************************************************************//**
Reinitialize the original tablespace header with the same space id
for single tablespace */
UNIV_INTERN
void
fil_reinit_space_header(
/*====================*/
	ulint		id,	/*!< in: space id */
	ulint		size);	/*!< in: size in blocks */
/*******************************************************************//**
Closes a single-table tablespace. The tablespace must be cached in the
memory cache. Free all pages used by the tablespace.
@return	DB_SUCCESS or error */
UNIV_INTERN
dberr_t
fil_close_tablespace(
/*=================*/
	trx_t*	trx,	/*!< in/out: Transaction covering the close */
	ulint	id);	/*!< in: space id */
#ifndef UNIV_HOTBACKUP
/*******************************************************************//**
Discards a single-table tablespace. The tablespace must be cached in the
memory cache. Discarding is like deleting a tablespace, but

 1. We do not drop the table from the data dictionary;

 2. We remove all insert buffer entries for the tablespace immediately;
    in DROP TABLE they are only removed gradually in the background;

 3. When the user does IMPORT TABLESPACE, the tablespace will have the
    same id as it originally had.

 4. Free all the pages in use by the tablespace if rename=TRUE.
@return	DB_SUCCESS or error */
UNIV_INTERN
dberr_t
fil_discard_tablespace(
/*===================*/
	ulint	id)	/*!< in: space id */
	__attribute__((warn_unused_result));
#endif /* !UNIV_HOTBACKUP */
/*******************************************************************//**
Renames a single-table tablespace. The tablespace must be cached in the
tablespace memory cache.
@return	TRUE if success */
UNIV_INTERN
ibool
fil_rename_tablespace(
/*==================*/
	const char*	old_name_in,	/*!< in: old table name in the
					standard databasename/tablename
					format of InnoDB, or NULL if we
					do the rename based on the space
					id only */
	ulint		id,		/*!< in: space id */
	const char*	new_name,	/*!< in: new table name in the
					standard databasename/tablename
					format of InnoDB */
	const char*	new_path);	/*!< in: new full datafile path
					if the tablespace is remotely
					located, or NULL if it is located
					in the normal data directory. */

/*******************************************************************//**
Allocates a file name for a single-table tablespace. The string must be freed
by caller with mem_free().
@return	own: file name */
UNIV_INTERN
char*
fil_make_ibd_name(
/*==============*/
	const char*	name,		/*!< in: table name or a dir path */
	bool		is_full_path);	/*!< in: TRUE if it is a dir path */
/*******************************************************************//**
Allocates a file name for a tablespace ISL file (InnoDB Symbolic Link).
The string must be freed by caller with mem_free().
@return	own: file name */
UNIV_INTERN
char*
fil_make_isl_name(
/*==============*/
	const char*	name);	/*!< in: table name */
/*******************************************************************//**
Creates a new InnoDB Symbolic Link (ISL) file.  It is always created
under the 'datadir' of MySQL. The datadir is the directory of a
running mysqld program. We can refer to it by simply using the path '.'.
@return	DB_SUCCESS or error code */
UNIV_INTERN
dberr_t
fil_create_link_file(
/*=================*/
	const char*	tablename,	/*!< in: tablename */
	const char*	filepath);	/*!< in: pathname of tablespace */
/*******************************************************************//**
Deletes an InnoDB Symbolic Link (ISL) file. */
UNIV_INTERN
void
fil_delete_link_file(
/*==================*/
	const char*	tablename);	/*!< in: name of table */
/*******************************************************************//**
Reads an InnoDB Symbolic Link (ISL) file.
It is always created under the 'datadir' of MySQL.  The name is of the
form {databasename}/{tablename}. and the isl file is expected to be in a
'{databasename}' directory called '{tablename}.isl'. The caller must free
the memory of the null-terminated path returned if it is not null.
@return	own: filepath found in link file, NULL if not found. */
UNIV_INTERN
char*
fil_read_link_file(
/*===============*/
	const char*	name);		/*!< in: tablespace name */
/*******************************************************************//**
Creates a new single-table tablespace to a database directory of MySQL.
Database directories are under the 'datadir' of MySQL. The datadir is the
directory of a running mysqld program. We can refer to it by simply the
path '.'. Tables created with CREATE TEMPORARY TABLE we place in the temp
dir of the mysqld server.
@return	DB_SUCCESS or error code */
UNIV_INTERN
dberr_t
fil_create_new_single_table_tablespace(
/*===================================*/
	ulint		space_id,	/*!< in: space id */
	const char*	tablename,	/*!< in: the table name in the usual
					databasename/tablename format
					of InnoDB */
	const char*	dir_path,	/*!< in: NULL or a dir path */
	ulint		flags,		/*!< in: tablespace flags */
	ulint		flags2,		/*!< in: table flags2 */
	ulint		size)		/*!< in: the initial size of the
					tablespace file in pages,
					must be >= FIL_IBD_FILE_INITIAL_SIZE */
	__attribute__((nonnull, warn_unused_result));
#ifndef UNIV_HOTBACKUP
/********************************************************************//**
Tries to open a single-table tablespace and optionally checks the space id is
right in it. If does not succeed, prints an error message to the .err log. This
function is used to open a tablespace when we start up mysqld, and also in
IMPORT TABLESPACE.
NOTE that we assume this operation is used either at the database startup
or under the protection of the dictionary mutex, so that two users cannot
race here. This operation does not leave the file associated with the
tablespace open, but closes it after we have looked at the space id in it.

If the validate boolean is set, we read the first page of the file and
check that the space id in the file is what we expect. We assume that
this function runs much faster if no check is made, since accessing the
file inode probably is much faster (the OS caches them) than accessing
the first page of the file.  This boolean may be initially FALSE, but if
a remote tablespace is found it will be changed to true.

If the fix_dict boolean is set, then it is safe to use an internal SQL
statement to update the dictionary tables if they are incorrect.

@return	DB_SUCCESS or error code */
UNIV_INTERN
dberr_t
fil_open_single_table_tablespace(
/*=============================*/
	bool		validate,	/*!< in: Do we validate tablespace? */
	bool		fix_dict,	/*!< in: Can we fix the dictionary? */
	ulint		id,		/*!< in: space id */
	ulint		flags,		/*!< in: tablespace flags */
	const char*	tablename,	/*!< in: table name in the
					databasename/tablename format */
	const char*	filepath)	/*!< in: tablespace filepath */
	__attribute__((nonnull(5), warn_unused_result));

#endif /* !UNIV_HOTBACKUP */
/********************************************************************//**
At the server startup, if we need crash recovery, scans the database
directories under the MySQL datadir, looking for .ibd files. Those files are
single-table tablespaces. We need to know the space id in each of them so that
we know into which file we should look to check the contents of a page stored
in the doublewrite buffer, also to know where to apply log records where the
space id is != 0.
@return	DB_SUCCESS or error number */
UNIV_INTERN
dberr_t
fil_load_single_table_tablespaces(void);
/*===================================*/
/*******************************************************************//**
Returns TRUE if a single-table tablespace does not exist in the memory cache,
or is being deleted there.
@return	TRUE if does not exist or is being deleted */
UNIV_INTERN
ibool
fil_tablespace_deleted_or_being_deleted_in_mem(
/*===========================================*/
	ulint		id,	/*!< in: space id */
	ib_int64_t	version);/*!< in: tablespace_version should be this; if
				you pass -1 as the value of this, then this
				parameter is ignored */
/*******************************************************************//**
Returns TRUE if a single-table tablespace exists in the memory cache.
@return	TRUE if exists */
UNIV_INTERN
ibool
fil_tablespace_exists_in_mem(
/*=========================*/
	ulint	id);	/*!< in: space id */
#ifndef UNIV_HOTBACKUP
/*******************************************************************//**
Returns TRUE if a matching tablespace exists in the InnoDB tablespace memory
cache. Note that if we have not done a crash recovery at the database startup,
there may be many tablespaces which are not yet in the memory cache.
@return	TRUE if a matching tablespace exists in the memory cache */
UNIV_INTERN
ibool
fil_space_for_table_exists_in_mem(
/*==============================*/
	ulint		id,		/*!< in: space id */
	const char*	name,		/*!< in: table name in the standard
					'databasename/tablename' format */
	bool		print_error_if_does_not_exist,
					/*!< in: print detailed error
					information to the .err log if a
					matching tablespace is not found from
					memory */
	bool		adjust_space,	/*!< in: whether to adjust space id
					when find table space mismatch */
	mem_heap_t*	heap,		/*!< in: heap memory */
	table_id_t	table_id);	/*!< in: table id */
#else /* !UNIV_HOTBACKUP */
/********************************************************************//**
Extends all tablespaces to the size stored in the space header. During the
ibbackup --apply-log phase we extended the spaces on-demand so that log records
could be appllied, but that may have left spaces still too small compared to
the size stored in the space header. */
UNIV_INTERN
void
fil_extend_tablespaces_to_stored_len(void);
/*======================================*/
#endif /* !UNIV_HOTBACKUP */
/**********************************************************************//**
Tries to extend a data file so that it would accommodate the number of pages
given. The tablespace must be cached in the memory cache. If the space is big
enough already, does nothing.
@return	TRUE if success */
UNIV_INTERN
ibool
fil_extend_space_to_desired_size(
/*=============================*/
	ulint*	actual_size,	/*!< out: size of the space after extension;
				if we ran out of disk space this may be lower
				than the desired size */
	ulint	space_id,	/*!< in: space id */
	ulint	size_after_extend);/*!< in: desired size in pages after the
				extension; if the current space size is bigger
				than this already, the function does nothing */
/*******************************************************************//**
Tries to reserve free extents in a file space.
@return	TRUE if succeed */
UNIV_INTERN
ibool
fil_space_reserve_free_extents(
/*===========================*/
	ulint	id,		/*!< in: space id */
	ulint	n_free_now,	/*!< in: number of free extents now */
	ulint	n_to_reserve);	/*!< in: how many one wants to reserve */
/*******************************************************************//**
Releases free extents in a file space. */
UNIV_INTERN
void
fil_space_release_free_extents(
/*===========================*/
	ulint	id,		/*!< in: space id */
	ulint	n_reserved);	/*!< in: how many one reserved */
/*******************************************************************//**
Gets the number of reserved extents. If the database is silent, this number
should be zero. */
UNIV_INTERN
ulint
fil_space_get_n_reserved_extents(
/*=============================*/
	ulint	id);		/*!< in: space id */
/********************************************************************//**
Reads or writes data. This operation is asynchronous (aio).
@return DB_SUCCESS, or DB_TABLESPACE_DELETED if we are trying to do
i/o on a tablespace which does not exist */
UNIV_INTERN
dberr_t
fil_io(
/*===*/
	ulint	type,		/*!< in: OS_FILE_READ or OS_FILE_WRITE,
				ORed to OS_FILE_LOG, if a log i/o
				and ORed to OS_AIO_SIMULATED_WAKE_LATER
				if simulated aio and we want to post a
				batch of i/os; NOTE that a simulated batch
				may introduce hidden chances of deadlocks,
				because i/os are not actually handled until
				all have been posted: use with great
				caution! */
	bool	sync,		/*!< in: true if synchronous aio is desired */
	ulint	space_id,	/*!< in: space id */
	ulint	zip_size,	/*!< in: compressed page size in bytes;
				0 for uncompressed pages */
	ulint	block_offset,	/*!< in: offset in number of blocks */
	ulint	byte_offset,	/*!< in: remainder of offset in bytes; in
				aio this must be divisible by the OS block
				size */
	ulint	len,		/*!< in: how many bytes to read or write; this
				must not cross a file boundary; in aio this
				must be a block size multiple */
	void*	buf,		/*!< in/out: buffer where to store read data
				or from where to write; in aio this must be
				appropriately aligned */
	void*	message)	/*!< in: message for aio handler if non-sync
				aio used, else ignored */
	__attribute__((nonnull(8)));
/**********************************************************************//**
Waits for an aio operation to complete. This function is used to write the
handler for completed requests. The aio array of pending requests is divided
into segments (see os0file.cc for more info). The thread specifies which
segment it wants to wait for. */
UNIV_INTERN
void
fil_aio_wait(
/*=========*/
	ulint	segment);	/*!< in: the number of the segment in the aio
				array to wait for */
/**********************************************************************//**
Flushes to disk possible writes cached by the OS. If the space does not exist
or is being dropped, does not do anything. */
UNIV_INTERN
void
fil_flush(
/*======*/
	ulint	space_id);	/*!< in: file space id (this can be a group of
				log files or a tablespace of the database) */
/**********************************************************************//**
Flushes to disk writes in file spaces of the given type possibly cached by
the OS. */
UNIV_INTERN
void
fil_flush_file_spaces(
/*==================*/
	ulint	purpose);	/*!< in: FIL_TABLESPACE, FIL_LOG */
/******************************************************************//**
Checks the consistency of the tablespace cache.
@return	TRUE if ok */
UNIV_INTERN
ibool
fil_validate(void);
/*==============*/
/********************************************************************//**
Returns TRUE if file address is undefined.
@return	TRUE if undefined */
UNIV_INTERN
ibool
fil_addr_is_null(
/*=============*/
	fil_addr_t	addr);	/*!< in: address */
/********************************************************************//**
Get the predecessor of a file page.
@return	FIL_PAGE_PREV */
UNIV_INTERN
ulint
fil_page_get_prev(
/*==============*/
	const byte*	page);	/*!< in: file page */
/********************************************************************//**
Get the successor of a file page.
@return	FIL_PAGE_NEXT */
UNIV_INTERN
ulint
fil_page_get_next(
/*==============*/
	const byte*	page);	/*!< in: file page */
/*********************************************************************//**
Sets the file page type. */
UNIV_INTERN
void
fil_page_set_type(
/*==============*/
	byte*	page,	/*!< in/out: file page */
	ulint	type);	/*!< in: type */
/*********************************************************************//**
Gets the file page type.
@return type; NOTE that if the type has not been written to page, the
return value not defined */
UNIV_INTERN
ulint
fil_page_get_type(
/*==============*/
	const byte*	page);	/*!< in: file page */

/*******************************************************************//**
Returns TRUE if a single-table tablespace is being deleted.
@return TRUE if being deleted */
UNIV_INTERN
ibool
fil_tablespace_is_being_deleted(
/*============================*/
	ulint		id);	/*!< in: space id */

/********************************************************************//**
Delete the tablespace file and any related files like .cfg.
This should not be called for temporary tables. */
UNIV_INTERN
void
fil_delete_file(
/*============*/
	const char*	path);	/*!< in: filepath of the ibd tablespace */

/** Callback functor. */
struct PageCallback {

	/**
	Default constructor */
	PageCallback()
		:
		m_zip_size(),
		m_page_size(),
		m_filepath() UNIV_NOTHROW {}

	virtual ~PageCallback() UNIV_NOTHROW {}

	/**
	Called for page 0 in the tablespace file at the start.
	@param file_size - size of the file in bytes
	@param block - contents of the first page in the tablespace file
	@retval DB_SUCCESS or error code.*/
	virtual dberr_t init(
		os_offset_t		file_size,
		const buf_block_t*	block) UNIV_NOTHROW = 0;

	/**
	Called for every page in the tablespace. If the page was not
	updated then its state must be set to BUF_PAGE_NOT_USED. For
	compressed tables the page descriptor memory will be at offset:
       		block->frame + UNIV_PAGE_SIZE;
	@param offset - physical offset within the file
	@param block - block read from file, note it is not from the buffer pool
	@retval DB_SUCCESS or error code. */
	virtual dberr_t operator()(
		os_offset_t 	offset,
		buf_block_t*	block) UNIV_NOTHROW = 0;

	/**
	Set the name of the physical file and the file handle that is used
	to open it for the file that is being iterated over.
	@param filename - then physical name of the tablespace file.
	@param file - OS file handle */
	void set_file(const char* filename, os_file_t file) UNIV_NOTHROW
	{
		m_file = file;
		m_filepath = filename;
	}

	/**
	@return the space id of the tablespace */
	virtual ulint get_space_id() const UNIV_NOTHROW = 0;

	/** The compressed page size
	@return the compressed page size */
	ulint get_zip_size() const
	{
		return(m_zip_size);
	}

	/**
	Set the tablespace compressed table size.
	@return DB_SUCCESS if it is valie or DB_CORRUPTION if not */
	dberr_t set_zip_size(const buf_frame_t* page) UNIV_NOTHROW;

	/** The compressed page size
	@return the compressed page size */
	ulint get_page_size() const
	{
		return(m_page_size);
	}

	/** Compressed table page size */
	ulint			m_zip_size;

	/** The tablespace page size. */
	ulint			m_page_size;

	/** File handle to the tablespace */
	os_file_t		m_file;

	/** Physical file path. */
	const char*		m_filepath;

protected:
	// Disable copying
	PageCallback(const PageCallback&);
	PageCallback& operator=(const PageCallback&);
};

/********************************************************************//**
Iterate over all the pages in the tablespace.
@param table - the table definiton in the server
@param n_io_buffers - number of blocks to read and write together
@param callback - functor that will do the page updates
@return	DB_SUCCESS or error code */
UNIV_INTERN
dberr_t
fil_tablespace_iterate(
/*===================*/
	dict_table_t*		table,
	ulint			n_io_buffers,
	PageCallback&		callback)
	__attribute__((nonnull, warn_unused_result));

/*******************************************************************//**
Checks if a single-table tablespace for a given table name exists in the
tablespace memory cache.
@return	space id, ULINT_UNDEFINED if not found */
UNIV_INTERN
ulint
fil_get_space_id_for_table(
/*=======================*/
	const char*	name);	/*!< in: table name in the standard
				'databasename/tablename' format */

/**
Iterate over all the spaces in the space list and fetch the
tablespace names. It will return a copy of the name that must be
freed by the caller using: delete[].
@return DB_SUCCESS if all OK. */
UNIV_INTERN
dberr_t
fil_get_space_names(
/*================*/
	space_name_list_t&	space_name_list)
				/*!< in/out: Vector for collecting the names. */
	__attribute__((warn_unused_result));

/****************************************************************//**
Generate redo logs for swapping two .ibd files */
UNIV_INTERN
void
fil_mtr_rename_log(
/*===============*/
	ulint		old_space_id,	/*!< in: tablespace id of the old
					table. */
	const char*	old_name,	/*!< in: old table name */
	ulint		new_space_id,	/*!< in: tablespace id of the new
					table */
	const char*	new_name,	/*!< in: new table name */
	const char*	tmp_name,	/*!< in: temp table name used while
					swapping */
	mtr_t*		mtr)		/*!< in/out: mini-transaction */
	__attribute__((nonnull));

#endif /* !UNIV_INNOCHECKSUM */
#endif /* fil0fil_h */
