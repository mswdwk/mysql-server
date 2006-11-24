/*   Innobase relational database engine; Copyright (C) 2001 Innobase Oy

     This program is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License 2
     as published by the Free Software Foundation in June 1991.

     This program is distributed in the hope that it will be useful,
     but WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
     GNU General Public License for more details.

     You should have received a copy of the GNU General Public License 2
     along with this program (in file COPYING); if not, write to the Free
     Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA. */
/******************************************************
The database buffer pool high-level routines

(c) 1995 Innobase Oy

Created 11/5/1995 Heikki Tuuri
*******************************************************/

#ifndef buf0buf_h
#define buf0buf_h

#include "univ.i"
#include "fil0fil.h"
#include "mtr0types.h"
#include "buf0types.h"
#include "sync0rw.h"
#include "hash0hash.h"
#include "ut0byte.h"
#include "os0proc.h"
#include "page0types.h"

/* Flags for flush types */
#define BUF_FLUSH_LRU		1
#define BUF_FLUSH_SINGLE_PAGE	2
#define BUF_FLUSH_LIST		3	/* An array in the pool struct
					has size BUF_FLUSH_LIST + 1: if you
					add more flush types, put them in
					the middle! */
/* Modes for buf_page_get_gen */
#define BUF_GET			10	/* get always */
#define	BUF_GET_IF_IN_POOL	11	/* get if in pool */
#define	BUF_GET_NOWAIT		12	/* get if can set the latch without
					waiting */
#define BUF_GET_NO_LATCH	14	/* get and bufferfix, but set no latch;
					we have separated this case, because
					it is error-prone programming not to
					set a latch, and it should be used
					with care */
/* Modes for buf_page_get_known_nowait */
#define BUF_MAKE_YOUNG	51
#define BUF_KEEP_OLD	52
/* Magic value to use instead of checksums when they are disabled */
#define BUF_NO_CHECKSUM_MAGIC 0xDEADBEEFUL

extern buf_pool_t*	buf_pool;	/* The buffer pool of the database */
#ifdef UNIV_DEBUG
extern ibool		buf_debug_prints;/* If this is set TRUE, the program
					prints info whenever read or flush
					occurs */
#endif /* UNIV_DEBUG */
extern ulint srv_buf_pool_write_requests; /* variable to count write request
					  issued */

/* States of a control block */
enum buf_page_state {
	BUF_BLOCK_ZIP_PAGE = 1,		/* contains a compressed page only;
					must be smaller than
					BUF_BLOCK_NOT_USED;
					cf. buf_block_state_valid() */
	BUF_BLOCK_NOT_USED,		/* is in the free list */
	BUF_BLOCK_READY_FOR_USE,	/* when buf_get_free_block returns
					a block, it is in this state */
	BUF_BLOCK_FILE_PAGE,		/* contains a buffered file page */
	BUF_BLOCK_MEMORY,		/* contains some main memory object */
	BUF_BLOCK_REMOVE_HASH		/* hash index should be removed
					before putting to the free list */
};

/************************************************************************
Creates the buffer pool. */

buf_pool_t*
buf_pool_init(void);
/*===============*/
				/* out, own: buf_pool object, NULL if not
				enough memory or error */
/************************************************************************
Resizes the buffer pool. */

void
buf_pool_resize(void);
/*=================*/
/*************************************************************************
Gets the current size of buffer buf_pool in bytes. */
UNIV_INLINE
ulint
buf_pool_get_curr_size(void);
/*========================*/
			/* out: size in bytes */
/************************************************************************
Gets the smallest oldest_modification lsn for any page in the pool. Returns
zero if all modified pages have been flushed to disk. */
UNIV_INLINE
ib_ulonglong
buf_pool_get_oldest_modification(void);
/*==================================*/
				/* out: oldest modification in pool,
				zero if none */
/************************************************************************
Allocates a buffer block. */
UNIV_INLINE
buf_block_t*
buf_block_alloc(
/*============*/
				/* out, own: the allocated block */
	ulint	zip_size);	/* in: compressed page size in bytes,
				or 0 if uncompressed tablespace */
/************************************************************************
Frees a buffer block which does not contain a file page. */
UNIV_INLINE
void
buf_block_free(
/*===========*/
	buf_block_t*	block);	/* in, own: block to be freed */
/*************************************************************************
Copies contents of a buffer frame to a given buffer. */
UNIV_INLINE
byte*
buf_frame_copy(
/*===========*/
					/* out: buf */
	byte*			buf,	/* in: buffer to copy to */
	const buf_frame_t*	frame);	/* in: buffer frame */
/******************************************************************
NOTE! The following macros should be used instead of buf_page_get_gen,
to improve debugging. Only values RW_S_LATCH and RW_X_LATCH are allowed
in LA! */
#define buf_page_get(SP, OF, LA, MTR)	 buf_page_get_gen(\
				SP, OF, LA, NULL,\
				BUF_GET, __FILE__, __LINE__, MTR)
/******************************************************************
Use these macros to bufferfix a page with no latching. Remember not to
read the contents of the page unless you know it is safe. Do not modify
the contents of the page! We have separated this case, because it is
error-prone programming not to set a latch, and it should be used
with care. */
#define buf_page_get_with_no_latch(SP, OF, MTR)	   buf_page_get_gen(\
				SP, OF, RW_NO_LATCH, NULL,\
				BUF_GET_NO_LATCH, __FILE__, __LINE__, MTR)
/******************************************************************
NOTE! The following macros should be used instead of buf_page_get_gen, to
improve debugging. Only values RW_S_LATCH and RW_X_LATCH are allowed as LA! */
#define buf_page_get_nowait(SP, OF, LA, MTR)	buf_page_get_gen(\
				SP, OF, LA, NULL,\
				BUF_GET_NOWAIT, __FILE__, __LINE__, MTR)
/******************************************************************
NOTE! The following macros should be used instead of
buf_page_optimistic_get_func, to improve debugging. Only values RW_S_LATCH and
RW_X_LATCH are allowed as LA! */
#define buf_page_optimistic_get(LA, BL, MC, MTR)			     \
	buf_page_optimistic_get_func(LA, BL, MC, __FILE__, __LINE__, MTR)
/************************************************************************
This is the general function used to get optimistic access to a database
page. */

ibool
buf_page_optimistic_get_func(
/*=========================*/
				/* out: TRUE if success */
	ulint		rw_latch,/* in: RW_S_LATCH, RW_X_LATCH */
	buf_block_t*	block,	/* in: guessed block */
	ib_ulonglong	modify_clock,/* in: modify clock value if mode is
				..._GUESS_ON_CLOCK */
	const char*	file,	/* in: file name */
	ulint		line,	/* in: line where called */
	mtr_t*		mtr);	/* in: mini-transaction */
/************************************************************************
Tries to get the page, but if file io is required, releases all latches
in mtr down to the given savepoint. If io is required, this function
retrieves the page to buffer buf_pool, but does not bufferfix it or latch
it. */
UNIV_INLINE
buf_block_t*
buf_page_get_release_on_io(
/*=======================*/
				/* out: pointer to the block, or NULL
				if not in buffer buf_pool */
	ulint	space,		/* in: space id */
	ulint	offset,		/* in: offset of the page within space
				in units of a page */
	buf_block_t* guess,	/* in: guessed frame or NULL */
	ulint	rw_latch,	/* in: RW_X_LATCH, RW_S_LATCH,
				or RW_NO_LATCH */
	ulint	savepoint,	/* in: mtr savepoint */
	mtr_t*	mtr);		/* in: mtr */
/************************************************************************
This is used to get access to a known database page, when no waiting can be
done. */

ibool
buf_page_get_known_nowait(
/*======================*/
				/* out: TRUE if success */
	ulint		rw_latch,/* in: RW_S_LATCH, RW_X_LATCH */
	buf_block_t*	block,	/* in: the known page */
	ulint		mode,	/* in: BUF_MAKE_YOUNG or BUF_KEEP_OLD */
	const char*	file,	/* in: file name */
	ulint		line,	/* in: line where called */
	mtr_t*		mtr);	/* in: mini-transaction */
/************************************************************************
This is the general function used to get access to a database page. */

buf_block_t*
buf_page_get_gen(
/*=============*/
				/* out: pointer to the block or NULL */
	ulint		space,	/* in: space id */
	ulint		offset,	/* in: page number */
	ulint		rw_latch,/* in: RW_S_LATCH, RW_X_LATCH, RW_NO_LATCH */
	buf_block_t*	guess,	/* in: guessed block or NULL */
	ulint		mode,	/* in: BUF_GET, BUF_GET_IF_IN_POOL,
				BUF_GET_NO_LATCH */
	const char*	file,	/* in: file name */
	ulint		line,	/* in: line where called */
	mtr_t*		mtr);	/* in: mini-transaction */
/************************************************************************
Initializes a page to the buffer buf_pool. The page is usually not read
from a file even if it cannot be found in the buffer buf_pool. This is one
of the functions which perform to a block a state transition NOT_USED =>
FILE_PAGE (the other is buf_page_init_for_read above). */

buf_block_t*
buf_page_create(
/*============*/
			/* out: pointer to the block, page bufferfixed */
	ulint	space,	/* in: space id */
	ulint	offset,	/* in: offset of the page within space in units of
			a page */
	ulint	zip_size,/* in: compressed page size, or 0 */
	mtr_t*	mtr);	/* in: mini-transaction handle */
#ifdef UNIV_HOTBACKUP
/************************************************************************
Inits a page to the buffer buf_pool, for use in ibbackup --restore. */

void
buf_page_init_for_backup_restore(
/*=============================*/
	ulint		space,	/* in: space id */
	ulint		offset,	/* in: offset of the page within space
				in units of a page */
	ulint		zip_size,/* in: compressed page size in bytes
				or 0 for uncompressed pages */
	buf_block_t*	block);	/* in: block to init */
#endif /* UNIV_HOTBACKUP */
/************************************************************************
Decrements the bufferfix count of a buffer control block and releases
a latch, if specified. */
UNIV_INLINE
void
buf_page_release(
/*=============*/
	buf_block_t*	block,		/* in: buffer block */
	ulint		rw_latch,	/* in: RW_S_LATCH, RW_X_LATCH,
					RW_NO_LATCH */
	mtr_t*		mtr);		/* in: mtr */
/************************************************************************
Moves a page to the start of the buffer pool LRU list. This high-level
function can be used to prevent an important page from from slipping out of
the buffer pool. */

void
buf_page_make_young(
/*================*/
	buf_block_t*	block);	/* in: buffer block of a file page */
/************************************************************************
Returns TRUE if the page can be found in the buffer pool hash table. NOTE
that it is possible that the page is not yet read from disk, though. */

ibool
buf_page_peek(
/*==========*/
			/* out: TRUE if found from page hash table,
			NOTE that the page is not necessarily yet read
			from disk! */
	ulint	space,	/* in: space id */
	ulint	offset);/* in: page number */
/************************************************************************
Returns the buffer control block if the page can be found in the buffer
pool. NOTE that it is possible that the page is not yet read
from disk, though. This is a very low-level function: use with care! */

buf_block_t*
buf_page_peek_block(
/*================*/
			/* out: control block if found from page hash table,
			otherwise NULL; NOTE that the page is not necessarily
			yet read from disk! */
	ulint	space,	/* in: space id */
	ulint	offset);/* in: page number */
/************************************************************************
Resets the check_index_page_at_flush field of a page if found in the buffer
pool. */

void
buf_reset_check_index_page_at_flush(
/*================================*/
	ulint	space,	/* in: space id */
	ulint	offset);/* in: page number */
#ifdef UNIV_DEBUG_FILE_ACCESSES
/************************************************************************
Sets file_page_was_freed TRUE if the page is found in the buffer pool.
This function should be called when we free a file page and want the
debug version to check that it is not accessed any more unless
reallocated. */

buf_block_t*
buf_page_set_file_page_was_freed(
/*=============================*/
			/* out: control block if found from page hash table,
			otherwise NULL */
	ulint	space,	/* in: space id */
	ulint	offset);/* in: page number */
/************************************************************************
Sets file_page_was_freed FALSE if the page is found in the buffer pool.
This function should be called when we free a file page and want the
debug version to check that it is not accessed any more unless
reallocated. */

buf_block_t*
buf_page_reset_file_page_was_freed(
/*===============================*/
			/* out: control block if found from page hash table,
			otherwise NULL */
	ulint	space,	/* in: space id */
	ulint	offset);	/* in: page number */
#endif /* UNIV_DEBUG_FILE_ACCESSES */
/************************************************************************
Recommends a move of a block to the start of the LRU list if there is danger
of dropping from the buffer pool. NOTE: does not reserve the buffer pool
mutex. */
UNIV_INLINE
ibool
buf_block_peek_if_too_old(
/*======================*/
				/* out: TRUE if should be made younger */
	buf_block_t*	block);	/* in: block to make younger */
/************************************************************************
Returns the current state of is_hashed of a page. FALSE if the page is
not in the pool. NOTE that this operation does not fix the page in the
pool if it is found there. */

ibool
buf_page_peek_if_search_hashed(
/*===========================*/
			/* out: TRUE if page hash index is built in search
			system */
	ulint	space,	/* in: space id */
	ulint	offset);/* in: page number */
/************************************************************************
Gets the youngest modification log sequence number for a frame.
Returns zero if not file page or no modification occurred yet. */
UNIV_INLINE
ib_ulonglong
buf_block_get_newest_modification(
/*==============================*/
				/* out: newest modification to page */
	buf_block_t*	block);	/* in: block containing the page frame */
/************************************************************************
Increments the modify clock of a frame by 1. The caller must (1) own the
buf_pool mutex and block bufferfix count has to be zero, (2) or own an x-lock
on the block. */
UNIV_INLINE
void
buf_block_modify_clock_inc(
/*=======================*/
	buf_block_t*	block);	/* in: block */
/************************************************************************
Returns the value of the modify clock. The caller must have an s-lock
or x-lock on the block. */
UNIV_INLINE
ib_ulonglong
buf_block_get_modify_clock(
/*=======================*/
				/* out: value */
	buf_block_t*	block);	/* in: block */
/************************************************************************
Calculates a page checksum which is stored to the page when it is written
to a file. Note that we must be careful to calculate the same value
on 32-bit and 64-bit architectures. */

ulint
buf_calc_page_new_checksum(
/*=======================*/
				/* out: checksum */
	const byte*	page);	/* in: buffer page */
/************************************************************************
In versions < 4.0.14 and < 4.1.1 there was a bug that the checksum only
looked at the first few bytes of the page. This calculates that old
checksum.
NOTE: we must first store the new formula checksum to
FIL_PAGE_SPACE_OR_CHKSUM before calculating and storing this old checksum
because this takes that field as an input! */

ulint
buf_calc_page_old_checksum(
/*=======================*/
				/* out: checksum */
	const byte*	 page);	/* in: buffer page */
/************************************************************************
Checks if a page is corrupt. */

ibool
buf_page_is_corrupted(
/*==================*/
					/* out: TRUE if corrupted */
	const byte*	read_buf,	/* in: a database page */
	ulint		zip_size);	/* in: size of compressed page;
					0 for uncompressed pages */
/**************************************************************************
Gets the space id, page offset, and byte offset within page of a
pointer pointing to a buffer frame containing a file page. */
UNIV_INLINE
void
buf_ptr_get_fsp_addr(
/*=================*/
	const void*	ptr,	/* in: pointer to a buffer frame */
	ulint*		space,	/* out: space id */
	fil_addr_t*	addr);	/* out: page offset and byte offset */
/**************************************************************************
Gets the hash value of a block. This can be used in searches in the
lock hash table. */
UNIV_INLINE
ulint
buf_block_get_lock_hash_val(
/*========================*/
					/* out: lock hash value */
	const buf_block_t*	block)	/* in: block */
	__attribute__((const));
#if defined UNIV_DEBUG || defined UNIV_BUF_DEBUG
/*************************************************************************
Validates the buffer pool data structure. */

ibool
buf_validate(void);
/*==============*/
#endif /* UNIV_DEBUG || UNIV_BUF_DEBUG */
#if defined UNIV_DEBUG_PRINT || defined UNIV_DEBUG || defined UNIV_BUF_DEBUG
/*************************************************************************
Prints info of the buffer pool data structure. */

void
buf_print(void);
/*============*/
#endif /* UNIV_DEBUG_PRINT || UNIV_DEBUG || UNIV_BUF_DEBUG */
/************************************************************************
Prints a page to stderr. */

void
buf_page_print(
/*===========*/
	const byte*	read_buf,	/* in: a database page */
	ulint		zip_size);	/* in: compressed page size, or
					0 for uncompressed pages */
/*************************************************************************
Returns the number of latched pages in the buffer pool. */

ulint
buf_get_latched_pages_number(void);
/*==============================*/
/*************************************************************************
Returns the number of pending buf pool ios. */

ulint
buf_get_n_pending_ios(void);
/*=======================*/
/*************************************************************************
Prints info of the buffer i/o. */

void
buf_print_io(
/*=========*/
	FILE*	file);	/* in: file where to print */
/*************************************************************************
Returns the ratio in percents of modified pages in the buffer pool /
database pages in the buffer pool. */

ulint
buf_get_modified_ratio_pct(void);
/*============================*/
/**************************************************************************
Refreshes the statistics used to print per-second averages. */

void
buf_refresh_io_stats(void);
/*======================*/
/*************************************************************************
Checks that all file pages in the buffer are in a replaceable state. */

ibool
buf_all_freed(void);
/*===============*/
/*************************************************************************
Checks that there currently are no pending i/o-operations for the buffer
pool. */

ibool
buf_pool_check_no_pending_io(void);
/*==============================*/
				/* out: TRUE if there is no pending i/o */
/*************************************************************************
Invalidates the file pages in the buffer pool when an archive recovery is
completed. All the file pages buffered must be in a replaceable state when
this function is called: not latched and not modified. */

void
buf_pool_invalidate(void);
/*=====================*/

/*========================================================================
--------------------------- LOWER LEVEL ROUTINES -------------------------
=========================================================================*/

#ifdef UNIV_SYNC_DEBUG
/*************************************************************************
Adds latch level info for the rw-lock protecting the buffer frame. This
should be called in the debug version after a successful latching of a
page if we know the latching order level of the acquired latch. */
UNIV_INLINE
void
buf_block_dbg_add_level(
/*====================*/
	buf_block_t*	block,	/* in: buffer page
				where we have acquired latch */
	ulint		level);	/* in: latching order level */
#endif /* UNIV_SYNC_DEBUG */
/*************************************************************************
Gets the state of a block. */
UNIV_INLINE
enum buf_page_state
buf_block_get_state(
/*================*/
					/* out: state */
	const buf_block_t*	block)	/* in: pointer to the control block */
	__attribute__((pure));
/*************************************************************************
Sets the state of a block. */
UNIV_INLINE
void
buf_block_set_state(
/*================*/
	buf_block_t*		block,	/* in/out: pointer to control block */
	enum buf_page_state	state);	/* in: state */
/*************************************************************************
Map a block to a file page. */
UNIV_INLINE
void
buf_block_set_file_page(
/*====================*/
	buf_block_t*		block,	/* in/out: pointer to control block */
	ulint			space,	/* in: tablespace id */
	ulint			page_no);/* in: page number */
/*************************************************************************
Gets a pointer to the memory frame of a block. */
UNIV_INLINE
buf_frame_t*
buf_block_get_frame(
/*================*/
				/* out: pointer to the frame */
	buf_block_t*	block)	/* in: pointer to the control block */
	__attribute__((const));
/*************************************************************************
Gets the space id of a block. */
UNIV_INLINE
ulint
buf_block_get_space(
/*================*/
					/* out: space id */
	const buf_block_t*	block)	/* in: pointer to the control block */
	__attribute((const));
/*************************************************************************
Gets the page number of a block. */
UNIV_INLINE
ulint
buf_block_get_page_no(
/*==================*/
					/* out: page number */
	const buf_block_t*	block)	/* in: pointer to the control block */
	__attribute((const));
/*************************************************************************
Gets the compressed page size of a block. */
UNIV_INLINE
ulint
buf_block_get_zip_size(
/*===================*/
					/* out: compressed page size, or 0 */
	const buf_block_t*	block)	/* in: pointer to the control block */
	__attribute((const));
/*************************************************************************
Gets the compressed page descriptor corresponding to an uncompressed page
if applicable. */
UNIV_INLINE
page_zip_des_t*
buf_block_get_page_zip(
/*===================*/
				/* out: compressed page descriptor, or NULL */
	buf_block_t*	block)	/* in: pointer to the control block */
	__attribute((const));
#if defined UNIV_DEBUG || defined UNIV_ZIP_DEBUG
/***********************************************************************
Gets the block to whose frame the pointer is pointing to. */
UNIV_INLINE
buf_block_t*
buf_block_align(
/*============*/
			/* out: pointer to block */
	byte*	ptr);	/* in: pointer to a frame */
/*************************************************************************
Gets the compressed page descriptor corresponding to an uncompressed page
if applicable. */
UNIV_INLINE
page_zip_des_t*
buf_frame_get_page_zip(
/*===================*/
			/* out: compressed page descriptor, or NULL */
	byte*	ptr)	/* in: pointer to the page */
	__attribute((const));
#endif /* UNIV_DEBUG || UNIV_ZIP_DEBUG */
/************************************************************************
This function is used to get info if there is an io operation
going on on a buffer page. */
UNIV_INLINE
ibool
buf_page_io_query(
/*==============*/
				/* out: TRUE if io going on */
	buf_block_t*	block);	/* in: pool block, must be bufferfixed */
/************************************************************************
Function which inits a page for read to the buffer buf_pool. If the page is
(1) already in buf_pool, or
(2) if we specify to read only ibuf pages and the page is not an ibuf page, or
(3) if the space is deleted or being deleted,
then this function does nothing.
Sets the io_fix flag to BUF_IO_READ and sets a non-recursive exclusive lock
on the buffer frame. The io-handler must take care that the flag is cleared
and the lock released later. This is one of the functions which perform the
state transition NOT_USED => FILE_PAGE to a block (the other is
buf_page_create). */

buf_block_t*
buf_page_init_for_read(
/*===================*/
				/* out: pointer to the block or NULL */
	ulint*		err,	/* out: DB_SUCCESS or DB_TABLESPACE_DELETED */
	ulint		mode,	/* in: BUF_READ_IBUF_PAGES_ONLY, ... */
	ulint		space,	/* in: space id */
	ulint		zip_size,/* in: compressed page size, or 0 */
	ib_longlong	tablespace_version,/* in: prevents reading from a wrong
				version of the tablespace in case we have done
				DISCARD + IMPORT */
	ulint		offset);/* in: page number */
/************************************************************************
Completes an asynchronous read or write request of a file page to or from
the buffer pool. */

void
buf_page_io_complete(
/*=================*/
	buf_block_t*	block);	/* in: pointer to the block in question */
/************************************************************************
Calculates a folded value of a file page address to use in the page hash
table. */
UNIV_INLINE
ulint
buf_page_address_fold(
/*==================*/
			/* out: the folded value */
	ulint	space,	/* in: space id */
	ulint	offset);/* in: offset of the page within space */
/**********************************************************************
Returns the control block of a file page, NULL if not found. */
UNIV_INLINE
buf_block_t*
buf_page_hash_get(
/*==============*/
			/* out: block, NULL if not found */
	ulint	space,	/* in: space id */
	ulint	offset);/* in: offset of the page within space */
/***********************************************************************
Increments the pool clock by one and returns its new value. Remember that
in the 32 bit version the clock wraps around at 4 billion! */
UNIV_INLINE
ulint
buf_pool_clock_tic(void);
/*====================*/
			/* out: new clock value */
/*************************************************************************
Gets the current length of the free list of buffer blocks. */

ulint
buf_get_free_list_len(void);
/*=======================*/



/* The common buffer control block structure
for compressed and uncompressed frames */

struct buf_page_struct{
	ulint		space:32;	/* tablespace id */
	ulint		offset:32;	/* page number */
	page_zip_des_t	zip;		/* compressed page; zip.state
					is relevant for all pages */
};

/* The buffer control block structure */

struct buf_block_struct{

	/* 1. General fields */

	buf_page_t	page;		/* page information; this must
					be the first field, so that
					buf_pool->page_hash can point
					to buf_page_t or buf_block_t */
	byte*		frame;		/* pointer to buffer frame which
					is of size UNIV_PAGE_SIZE, and
					aligned to an address divisible by
					UNIV_PAGE_SIZE */
	mutex_t		mutex;		/* mutex protecting this block:
					state (also protected by the buffer
					pool mutex), io_fix, buf_fix_count,
					and accessed; we introduce this new
					mutex in InnoDB-5.1 to relieve
					contention on the buffer pool mutex */
	rw_lock_t	lock;		/* read-write lock of the buffer
					frame */
	buf_block_t*	hash;		/* node used in chaining to the page
					hash table */
	ulint		lock_hash_val:32;/* hashed value of the page address
					in the record lock hash table */
	ulint		check_index_page_at_flush:1;
					/* TRUE if we know that this is
					an index page, and want the database
					to check its consistency before flush;
					note that there may be pages in the
					buffer pool which are index pages,
					but this flag is not set because
					we do not keep track of all pages */
	/* 2. Page flushing fields */

	UT_LIST_NODE_T(buf_block_t) flush_list;
					/* node of the modified, not yet
					flushed blocks list */
	ib_ulonglong	newest_modification;
					/* log sequence number of the youngest
					modification to this block, zero if
					not modified */
	ib_ulonglong	oldest_modification;
					/* log sequence number of the START of
					the log entry written of the oldest
					modification to this block which has
					not yet been flushed on disk; zero if
					all modifications are on disk */
	ulint		flush_type;	/* if this block is currently being
					flushed to disk, this tells the
					flush_type: BUF_FLUSH_LRU or
					BUF_FLUSH_LIST */

	/* 3. LRU replacement algorithm fields */

	UT_LIST_NODE_T(buf_block_t) free;
					/* node of the free block list */
	ibool		in_free_list;	/* TRUE if in the free list; used in
					debugging */
	UT_LIST_NODE_T(buf_block_t) LRU;
					/* node of the LRU list */
	ibool		in_LRU_list;	/* TRUE of the page is in the LRU list;
					used in debugging */
	ulint		LRU_position;	/* value which monotonically
					decreases (or may stay constant if
					the block is in the old blocks) toward
					the end of the LRU list, if the pool
					ulint_clock has not wrapped around:
					NOTE that this value can only be used
					in heuristic algorithms, because of
					the possibility of a wrap-around! */
	ulint		freed_page_clock;/* the value of freed_page_clock
					of the buffer pool when this block was
					the last time put to the head of the
					LRU list; a thread is allowed to
					read this for heuristic purposes
					without holding any mutex or latch */
	ibool		old;		/* TRUE if the block is in the old
					blocks in the LRU list */
	ulint		accessed:1;	/* TRUE if the page has been accessed
					while in the buffer pool: read-ahead
					may read in pages which have not been
					accessed yet; this is protected by
					block->mutex; a thread is allowed to
					read this for heuristic purposes
					without holding any mutex or latch */
	ulint		io_fix:2;	/* if a read is pending to the frame,
					io_fix is BUF_IO_READ, in the case
					of a write BUF_IO_WRITE, otherwise 0;
					this is protected by block->mutex */
	ulint		buf_fix_count:29;/* count of how manyfold this block
					is currently bufferfixed; this is
					protected by block->mutex */
	/* 4. Optimistic search field */

	ib_ulonglong	modify_clock;	/* this clock is incremented every
					time a pointer to a record on the
					page may become obsolete; this is
					used in the optimistic cursor
					positioning: if the modify clock has
					not changed, we know that the pointer
					is still valid; this field may be
					changed if the thread (1) owns the
					pool mutex and the page is not
					bufferfixed, or (2) the thread has an
					x-latch on the block */

	/* 5. Hash search fields: NOTE that the first 4 fields are NOT
	protected by any semaphore! */

	ulint		n_hash_helps;	/* counter which controls building
					of a new hash index for the page */
	ulint		n_fields;	/* recommended prefix length for hash
					search: number of full fields */
	ulint		n_bytes;	/* recommended prefix: number of bytes
					in an incomplete field */
	ibool		left_side;	/* TRUE or FALSE, depending on
					whether the leftmost record of several
					records with the same prefix should be
					indexed in the hash index */

	/* These 6 fields may only be modified when we have
	an x-latch on btr_search_latch AND
	a) we are holding an s-latch or x-latch on block->lock or
	b) we know that block->buf_fix_count == 0.

	An exception to this is when we init or create a page
	in the buffer pool in buf0buf.c. */

#ifdef UNIV_DEBUG
	ulint		n_pointers;	/* used in debugging: the number of
					pointers in the adaptive hash index
					pointing to this frame */
#endif /* UNIV_DEBUG */
	ulint		is_hashed:1;	/* TRUE if hash index has already been
					built on this page; note that it does
					not guarantee that the index is
					complete, though: there may have been
					hash collisions, record deletions,
					etc. */
	ulint		curr_n_fields:10;/* prefix length for hash indexing:
					number of full fields */
	ulint		curr_n_bytes:15;/* number of bytes in hash indexing */
	ibool		curr_left_side:1;/* TRUE or FALSE in hash indexing */
	dict_index_t*	index;		/* Index for which the adaptive
					hash index has been created. */
	/* 6. Debug fields */
#ifdef UNIV_SYNC_DEBUG
	rw_lock_t	debug_latch;	/* in the debug version, each thread
					which bufferfixes the block acquires
					an s-latch here; so we can use the
					debug utilities in sync0rw */
#endif
#ifdef UNIV_DEBUG_FILE_ACCESSES
	ibool		file_page_was_freed;
					/* this is set to TRUE when fsp
					frees a page in buffer pool */
#endif /* UNIV_DEBUG_FILE_ACCESSES */
};

/* Check if a block is in a valid state. */
#define buf_block_state_valid(block)		\
(buf_block_get_state(block) >= BUF_BLOCK_NOT_USED		\
 && (buf_block_get_state(block) <= BUF_BLOCK_REMOVE_HASH))

/* The buffer pool structure. NOTE! The definition appears here only for
other modules of this directory (buf) to see it. Do not use from outside! */

struct buf_pool_struct{

	/* 1. General fields */

	mutex_t		mutex;		/* mutex protecting the buffer pool
					struct and control blocks, except the
					read-write lock in them */
	ulint		n_chunks;	/* number of buffer pool chunks */
	buf_chunk_t*	chunks;		/* buffer pool chunks */
	ulint		curr_size;	/* current pool size in pages */
	hash_table_t*	page_hash;	/* hash table of the file pages */

	ulint		n_pend_reads;	/* number of pending read operations */

	time_t		last_printout_time; /* when buf_print was last time
					called */
	ulint		n_pages_read;	/* number read operations */
	ulint		n_pages_written;/* number write operations */
	ulint		n_pages_created;/* number of pages created in the pool
					with no read */
	ulint		n_page_gets;	/* number of page gets performed;
					also successful searches through
					the adaptive hash index are
					counted as page gets; this field
					is NOT protected by the buffer
					pool mutex */
	ulint		n_page_gets_old;/* n_page_gets when buf_print was
					last time called: used to calculate
					hit rate */
	ulint		n_pages_read_old;/* n_pages_read when buf_print was
					last time called */
	ulint		n_pages_written_old;/* number write operations */
	ulint		n_pages_created_old;/* number of pages created in
					the pool with no read */
	/* 2. Page flushing algorithm fields */

	UT_LIST_BASE_NODE_T(buf_block_t) flush_list;
					/* base node of the modified block
					list */
	ibool		init_flush[BUF_FLUSH_LIST + 1];
					/* this is TRUE when a flush of the
					given type is being initialized */
	ulint		n_flush[BUF_FLUSH_LIST + 1];
					/* this is the number of pending
					writes in the given flush type */
	os_event_t	no_flush[BUF_FLUSH_LIST + 1];
					/* this is in the set state when there
					is no flush batch of the given type
					running */
	ulint		ulint_clock;	/* a sequence number used to count
					time. NOTE! This counter wraps
					around at 4 billion (if ulint ==
					32 bits)! */
	ulint		freed_page_clock;/* a sequence number used to count the
					number of buffer blocks removed from
					the end of the LRU list; NOTE that
					this counter may wrap around at 4
					billion! A thread is allowed to
					read this for heuristic purposes
					without holding any mutex or latch */
	ulint		LRU_flush_ended;/* when an LRU flush ends for a page,
					this is incremented by one; this is
					set to zero when a buffer block is
					allocated */

	/* 3. LRU replacement algorithm fields */

	UT_LIST_BASE_NODE_T(buf_block_t) free;
					/* base node of the free block list */
	UT_LIST_BASE_NODE_T(buf_block_t) LRU;
					/* base node of the LRU list */
	buf_block_t*	LRU_old;	/* pointer to the about 3/8 oldest
					blocks in the LRU list; NULL if LRU
					length less than BUF_LRU_OLD_MIN_LEN */
	ulint		LRU_old_len;	/* length of the LRU list from
					the block to which LRU_old points
					onward, including that block;
					see buf0lru.c for the restrictions
					on this value; not defined if
					LRU_old == NULL */
};

/* Io_fix states of a control block; these must be 1..3 */
#define BUF_IO_READ		1
#define BUF_IO_WRITE		2

/************************************************************************
Let us list the consistency conditions for different control block states.

NOT_USED:	is in free list, not in LRU list, not in flush list, nor
		page hash table
READY_FOR_USE:	is not in free list, LRU list, or flush list, nor page
		hash table
MEMORY:		is not in free list, LRU list, or flush list, nor page
		hash table
FILE_PAGE:	space and offset are defined, is in page hash table
		if io_fix == BUF_IO_WRITE,
			pool: no_flush[block->flush_type] is in reset state,
			pool: n_flush[block->flush_type] > 0

		(1) if buf_fix_count == 0, then
			is in LRU list, not in free list
			is in flush list,
				if and only if oldest_modification > 0
			is x-locked,
				if and only if io_fix == BUF_IO_READ
			is s-locked,
				if and only if io_fix == BUF_IO_WRITE

		(2) if buf_fix_count > 0, then
			is not in LRU list, not in free list
			is in flush list,
				if and only if oldest_modification > 0
			if io_fix == BUF_IO_READ,
				is x-locked
			if io_fix == BUF_IO_WRITE,
				is s-locked

State transitions:

NOT_USED => READY_FOR_USE
READY_FOR_USE => MEMORY
READY_FOR_USE => FILE_PAGE
MEMORY => NOT_USED
FILE_PAGE => NOT_USED	NOTE: This transition is allowed if and only if
				(1) buf_fix_count == 0,
				(2) oldest_modification == 0, and
				(3) io_fix == 0.
*/

#ifndef UNIV_NONINL
#include "buf0buf.ic"
#endif

#endif
