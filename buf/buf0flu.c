/******************************************************
The database buffer buf_pool flush algorithm

(c) 1995-2001 Innobase Oy

Created 11/11/1995 Heikki Tuuri
*******************************************************/

#include "buf0flu.h"

#ifdef UNIV_NONINL
#include "buf0flu.ic"
#include "trx0sys.h"
#endif

#include "ut0byte.h"
#include "ut0lst.h"
#include "page0page.h"
#include "page0zip.h"
#include "fil0fil.h"
#include "buf0buf.h"
#include "buf0lru.h"
#include "buf0rea.h"
#include "ibuf0ibuf.h"
#include "log0log.h"
#include "os0file.h"
#include "trx0sys.h"
#include "srv0srv.h"

/* When flushed, dirty blocks are searched in neighborhoods of this size, and
flushed along with the original page. */

#define BUF_FLUSH_AREA		ut_min(BUF_READ_AHEAD_AREA,\
		buf_pool->curr_size / 16)

#if defined UNIV_DEBUG || defined UNIV_BUF_DEBUG
/**********************************************************************
Validates the flush list. */
static
ibool
buf_flush_validate_low(void);
/*========================*/
		/* out: TRUE if ok */
#endif /* UNIV_DEBUG || UNIV_BUF_DEBUG */

/************************************************************************
Inserts a modified block into the flush list. */

void
buf_flush_insert_into_flush_list(
/*=============================*/
	buf_page_t*	bpage)	/* in: block which is modified */
{
#ifdef UNIV_SYNC_DEBUG
	ut_ad(mutex_own(&(buf_pool->mutex)));
#endif /* UNIV_SYNC_DEBUG */

	ut_a(buf_page_in_file(bpage));

	ut_ad((UT_LIST_GET_FIRST(buf_pool->flush_list) == NULL)
	      || (UT_LIST_GET_FIRST(buf_pool->flush_list)->oldest_modification
		  <= bpage->oldest_modification));

	UT_LIST_ADD_FIRST(free_or_flush_list, buf_pool->flush_list, bpage);

#if defined UNIV_DEBUG || defined UNIV_BUF_DEBUG
	ut_a(buf_flush_validate_low());
#endif /* UNIV_DEBUG || UNIV_BUF_DEBUG */
}

/************************************************************************
Inserts a modified block into the flush list in the right sorted position.
This function is used by recovery, because there the modifications do not
necessarily come in the order of lsn's. */

void
buf_flush_insert_sorted_into_flush_list(
/*====================================*/
	buf_page_t*	bpage)	/* in: block which is modified */
{
	buf_page_t*	prev_b;
	buf_page_t*	b;

#ifdef UNIV_SYNC_DEBUG
	ut_ad(mutex_own(&(buf_pool->mutex)));
#endif /* UNIV_SYNC_DEBUG */

	prev_b = NULL;
	b = UT_LIST_GET_FIRST(buf_pool->flush_list);

	while (b && b->oldest_modification > bpage->oldest_modification) {
		prev_b = b;
		b = UT_LIST_GET_NEXT(free_or_flush_list, b);
	}

	if (prev_b == NULL) {
		UT_LIST_ADD_FIRST(free_or_flush_list,
				  buf_pool->flush_list, bpage);
	} else {
		UT_LIST_INSERT_AFTER(free_or_flush_list,
				     buf_pool->flush_list, prev_b, bpage);
	}

#if defined UNIV_DEBUG || defined UNIV_BUF_DEBUG
	ut_a(buf_flush_validate_low());
#endif /* UNIV_DEBUG || UNIV_BUF_DEBUG */
}

/************************************************************************
Returns TRUE if the file page block is immediately suitable for replacement,
i.e., the transition FILE_PAGE => NOT_USED allowed. */

ibool
buf_flush_ready_for_replace(
/*========================*/
				/* out: TRUE if can replace immediately */
	buf_page_t*	bpage)	/* in: buffer control block, must be
				buf_page_in_file(bpage) and in the LRU list */
{
#ifdef UNIV_SYNC_DEBUG
	ut_ad(mutex_own(&(buf_pool->mutex)));
	ut_ad(mutex_own(buf_page_get_mutex(bpage)));
#endif /* UNIV_SYNC_DEBUG */
	ut_ad(bpage->in_LRU_list);

	if (UNIV_LIKELY(buf_page_in_file(bpage))) {

		return(bpage->oldest_modification == 0
		       && buf_page_get_io_fix(bpage) == BUF_IO_NONE
		       && bpage->buf_fix_count == 0);
	}

	ut_print_timestamp(stderr);
	fprintf(stderr,
		"  InnoDB: Error: buffer block state %lu"
		" in the LRU list!\n",
		(ulong) buf_page_get_state(bpage));
	ut_print_buf(stderr, bpage, sizeof(buf_page_t));

	return(FALSE);
}

/************************************************************************
Returns TRUE if the block is modified and ready for flushing. */
UNIV_INLINE
ibool
buf_flush_ready_for_flush(
/*======================*/
				/* out: TRUE if can flush immediately */
	buf_page_t*	bpage,	/* in: buffer control block, must be
				buf_page_in_file(bpage) */
	enum buf_flush	flush_type)/* in: BUF_FLUSH_LRU or BUF_FLUSH_LIST */
{
	ut_a(buf_page_in_file(bpage));

#ifdef UNIV_SYNC_DEBUG
	ut_ad(mutex_own(&(buf_pool->mutex)));
	ut_ad(mutex_own(buf_page_get_mutex(bpage)));
#endif /* UNIV_SYNC_DEBUG */

	if (bpage->oldest_modification != 0
	    && buf_page_get_io_fix(bpage) == BUF_IO_NONE) {
		if (flush_type != BUF_FLUSH_LRU) {

			return(TRUE);

		} else if (bpage->buf_fix_count == 0) {

			/* If we are flushing the LRU list, to avoid deadlocks
			we require the block not to be bufferfixed, and hence
			not latched. */

			return(TRUE);
		}
	}

	return(FALSE);
}

/************************************************************************
Updates the flush system data structures when a write is completed. */

void
buf_flush_write_complete(
/*=====================*/
	buf_page_t*	bpage)	/* in: pointer to the block in question */
{
	enum buf_flush	flush_type;

	ut_ad(bpage);
#ifdef UNIV_SYNC_DEBUG
	ut_ad(mutex_own(&(buf_pool->mutex)));
#endif /* UNIV_SYNC_DEBUG */
	ut_a(buf_page_in_file(bpage));

	bpage->oldest_modification = 0;

	UT_LIST_REMOVE(free_or_flush_list, buf_pool->flush_list, bpage);

	ut_d(UT_LIST_VALIDATE(free_or_flush_list, buf_page_t,
			      buf_pool->flush_list));

	flush_type = buf_page_get_flush_type(bpage);
	buf_pool->n_flush[flush_type]--;

	if (flush_type == BUF_FLUSH_LRU) {
		/* Put the block to the end of the LRU list to wait to be
		moved to the free list */

		buf_LRU_make_block_old(bpage);

		buf_pool->LRU_flush_ended++;
	}

	/* fprintf(stderr, "n pending flush %lu\n",
	buf_pool->n_flush[flush_type]); */

	if ((buf_pool->n_flush[flush_type] == 0)
	    && (buf_pool->init_flush[flush_type] == FALSE)) {

		/* The running flush batch has ended */

		os_event_set(buf_pool->no_flush[flush_type]);
	}
}

/************************************************************************
Flushes possible buffered writes from the doublewrite memory buffer to disk,
and also wakes up the aio thread if simulated aio is used. It is very
important to call this function after a batch of writes has been posted,
and also when we may have to wait for a page latch! Otherwise a deadlock
of threads can occur. */
static
void
buf_flush_buffered_writes(void)
/*===========================*/
{
	buf_block_t*	block;
	byte*		write_buf;
	ulint		len;
	ulint		len2;
	ulint		i;

	if (!srv_use_doublewrite_buf || trx_doublewrite == NULL) {
		os_aio_simulated_wake_handler_threads();

		return;
	}

	mutex_enter(&(trx_doublewrite->mutex));

	/* Write first to doublewrite buffer blocks. We use synchronous
	aio and thus know that file write has been completed when the
	control returns. */

	if (trx_doublewrite->first_free == 0) {

		mutex_exit(&(trx_doublewrite->mutex));

		return;
	}

	for (i = 0; i < trx_doublewrite->first_free; i++) {

		block = trx_doublewrite->buf_block_arr[i];
		ut_a(buf_block_get_state(block) == BUF_BLOCK_FILE_PAGE);

		if (UNIV_LIKELY_NULL(block->page.zip.data)) {
			/* No simple validate for compressed pages exists. */
			continue;
		}

		if (UNIV_UNLIKELY
		    (memcmp(block->frame + (FIL_PAGE_LSN + 4),
			    block->frame + (UNIV_PAGE_SIZE
					    - FIL_PAGE_END_LSN_OLD_CHKSUM + 4),
			    4))) {
			ut_print_timestamp(stderr);
			fprintf(stderr,
				"  InnoDB: ERROR: The page to be written"
				" seems corrupt!\n"
				"InnoDB: The lsn fields do not match!"
				" Noticed in the buffer pool\n"
				"InnoDB: before posting to the"
				" doublewrite buffer.\n");
		}

		if (!block->check_index_page_at_flush) {
		} else if (page_is_comp(block->frame)) {
			if (UNIV_UNLIKELY
			    (!page_simple_validate_new(block->frame))) {
corrupted_page:
				buf_page_print(block->frame, 0);

				ut_print_timestamp(stderr);
				fprintf(stderr,
					"  InnoDB: Apparent corruption of an"
					" index page n:o %lu in space %lu\n"
					"InnoDB: to be written to data file."
					" We intentionally crash server\n"
					"InnoDB: to prevent corrupt data"
					" from ending up in data\n"
					"InnoDB: files.\n",
					(ulong) buf_block_get_page_no(block),
					(ulong) buf_block_get_space(block));

				ut_error;
			}
		} else if (UNIV_UNLIKELY
			   (!page_simple_validate_old(block->frame))) {

			goto corrupted_page;
		}
	}

	/* increment the doublewrite flushed pages counter */
	srv_dblwr_pages_written+= trx_doublewrite->first_free;
	srv_dblwr_writes++;

	len = ut_min(TRX_SYS_DOUBLEWRITE_BLOCK_SIZE,
		     trx_doublewrite->first_free) * UNIV_PAGE_SIZE;

	write_buf = trx_doublewrite->write_buf;
	i = 0;

	fil_io(OS_FILE_WRITE, TRUE, TRX_SYS_SPACE, 0,
	       trx_doublewrite->block1, 0, len,
	       (void*) write_buf, NULL);

	for (len2 = 0; len2 + UNIV_PAGE_SIZE <= len;
	     len2 += UNIV_PAGE_SIZE, i++) {
		block = trx_doublewrite->buf_block_arr[i];
		if (UNIV_LIKELY(!block->page.zip.data)
		    && UNIV_UNLIKELY
		    (memcmp(write_buf + len2 + (FIL_PAGE_LSN + 4),
			    write_buf + len2
			    + (UNIV_PAGE_SIZE
			       - FIL_PAGE_END_LSN_OLD_CHKSUM + 4), 4))) {
			ut_print_timestamp(stderr);
			fprintf(stderr,
				"  InnoDB: ERROR: The page to be written"
				" seems corrupt!\n"
				"InnoDB: The lsn fields do not match!"
				" Noticed in the doublewrite block1.\n");
		}
	}

	if (trx_doublewrite->first_free <= TRX_SYS_DOUBLEWRITE_BLOCK_SIZE) {
		goto flush;
	}

	len = (trx_doublewrite->first_free - TRX_SYS_DOUBLEWRITE_BLOCK_SIZE)
		* UNIV_PAGE_SIZE;

	write_buf = trx_doublewrite->write_buf
		+ TRX_SYS_DOUBLEWRITE_BLOCK_SIZE * UNIV_PAGE_SIZE;
	ut_ad(i == TRX_SYS_DOUBLEWRITE_BLOCK_SIZE);

	fil_io(OS_FILE_WRITE, TRUE, TRX_SYS_SPACE, 0,
	       trx_doublewrite->block2, 0, len,
	       (void*) write_buf, NULL);

	for (len2 = 0; len2 + UNIV_PAGE_SIZE <= len;
	     len2 += UNIV_PAGE_SIZE, i++) {
		block = trx_doublewrite->buf_block_arr[i];
		if (UNIV_LIKELY(!block->page.zip.data)
		    && UNIV_UNLIKELY
		    (memcmp(write_buf + len2 + (FIL_PAGE_LSN + 4),
			    write_buf + len2
			    + (UNIV_PAGE_SIZE
			       - FIL_PAGE_END_LSN_OLD_CHKSUM + 4), 4))) {
			ut_print_timestamp(stderr);
			fprintf(stderr,
				"  InnoDB: ERROR: The page to be"
				" written seems corrupt!\n"
				"InnoDB: The lsn fields do not match!"
				" Noticed in"
				" the doublewrite block2.\n");
		}
	}

flush:
	/* Now flush the doublewrite buffer data to disk */

	fil_flush(TRX_SYS_SPACE);

	/* We know that the writes have been flushed to disk now
	and in recovery we will find them in the doublewrite buffer
	blocks. Next do the writes to the intended positions. */

	for (i = 0; i < trx_doublewrite->first_free; i++) {
		block = trx_doublewrite->buf_block_arr[i];
		ut_a(buf_block_get_state(block) == BUF_BLOCK_FILE_PAGE);
		if (UNIV_UNLIKELY(buf_block_get_zip_size(block))) {
			fil_io(OS_FILE_WRITE | OS_AIO_SIMULATED_WAKE_LATER,
			       FALSE, buf_block_get_space(block),
			       buf_block_get_zip_size(block),
			       buf_block_get_page_no(block), 0,
			       buf_block_get_zip_size(block),
			       (void*)block->page.zip.data,
			       (void*)block);
			continue;
		} else if (UNIV_UNLIKELY
			   (memcmp(block->frame + (FIL_PAGE_LSN + 4),
				   block->frame
				   + (UNIV_PAGE_SIZE
				      - FIL_PAGE_END_LSN_OLD_CHKSUM + 4),
				   4))) {
			ut_print_timestamp(stderr);
			fprintf(stderr,
				"  InnoDB: ERROR: The page to be written"
				" seems corrupt!\n"
				"InnoDB: The lsn fields do not match!"
				" Noticed in the buffer pool\n"
				"InnoDB: after posting and flushing"
				" the doublewrite buffer.\n"
				"InnoDB: Page buf fix count %lu,"
				" io fix %lu, state %lu\n",
				(ulong)block->page.buf_fix_count,
				(ulong)buf_block_get_io_fix(block),
				(ulong)buf_block_get_state(block));
		}

		fil_io(OS_FILE_WRITE | OS_AIO_SIMULATED_WAKE_LATER,
		       FALSE, buf_block_get_space(block), 0,
		       buf_block_get_page_no(block), 0, UNIV_PAGE_SIZE,
		       (void*)block->frame, (void*)block);
	}

	/* Wake possible simulated aio thread to actually post the
	writes to the operating system */

	os_aio_simulated_wake_handler_threads();

	/* Wait that all async writes to tablespaces have been posted to
	the OS */

	os_aio_wait_until_no_pending_writes();

	/* Now we flush the data to disk (for example, with fsync) */

	fil_flush_file_spaces(FIL_TABLESPACE);

	/* We can now reuse the doublewrite memory buffer: */

	trx_doublewrite->first_free = 0;

	mutex_exit(&(trx_doublewrite->mutex));
}

/************************************************************************
Posts a buffer page for writing. If the doublewrite memory buffer is
full, calls buf_flush_buffered_writes and waits for for free space to
appear. */
static
void
buf_flush_post_to_doublewrite_buf(
/*==============================*/
	buf_block_t*	block)	/* in: buffer block to write */
{
	ulint	zip_size;
try_again:
	mutex_enter(&(trx_doublewrite->mutex));

	ut_a(buf_block_get_state(block) == BUF_BLOCK_FILE_PAGE);

	if (trx_doublewrite->first_free
	    >= 2 * TRX_SYS_DOUBLEWRITE_BLOCK_SIZE) {
		mutex_exit(&(trx_doublewrite->mutex));

		buf_flush_buffered_writes();

		goto try_again;
	}

	zip_size = buf_block_get_zip_size(block);

	if (UNIV_UNLIKELY(zip_size)) {
		/* Copy the compressed page and clear the rest. */
		memcpy(trx_doublewrite->write_buf
		       + UNIV_PAGE_SIZE * trx_doublewrite->first_free,
		       block->page.zip.data, zip_size);
		memset(trx_doublewrite->write_buf
		       + UNIV_PAGE_SIZE * trx_doublewrite->first_free
		       + zip_size, 0, UNIV_PAGE_SIZE - zip_size);
	} else {
		memcpy(trx_doublewrite->write_buf
		       + UNIV_PAGE_SIZE * trx_doublewrite->first_free,
		       block->frame, UNIV_PAGE_SIZE);
	}

	trx_doublewrite->buf_block_arr[trx_doublewrite->first_free] = block;

	trx_doublewrite->first_free++;

	if (trx_doublewrite->first_free
	    >= 2 * TRX_SYS_DOUBLEWRITE_BLOCK_SIZE) {
		mutex_exit(&(trx_doublewrite->mutex));

		buf_flush_buffered_writes();

		return;
	}

	mutex_exit(&(trx_doublewrite->mutex));
}

/************************************************************************
Initializes a page for writing to the tablespace. */

void
buf_flush_init_for_writing(
/*=======================*/
	byte*		page,		/* in/out: page */
	void*		page_zip_,	/* in/out: compressed page, or NULL */
	ib_uint64_t	newest_lsn)	/* in: newest modification lsn
					to the page */
{
	if (page_zip_) {
		page_zip_des_t*	page_zip = page_zip_;
		ulint		zip_size = page_zip_get_size(page_zip);
		ut_ad(zip_size);
		ut_ad(ut_is_2pow(zip_size));
		ut_ad(zip_size <= UNIV_PAGE_SIZE);

		switch (UNIV_EXPECT(fil_page_get_type(page), FIL_PAGE_INDEX)) {
		case FIL_PAGE_TYPE_ALLOCATED:
		case FIL_PAGE_INODE:
		case FIL_PAGE_IBUF_BITMAP:
		case FIL_PAGE_TYPE_FSP_HDR:
		case FIL_PAGE_TYPE_XDES:
			/* These are essentially uncompressed pages. */
			memcpy(page_zip->data, page, zip_size);
			/* fall through */
		case FIL_PAGE_TYPE_ZBLOB:
		case FIL_PAGE_INDEX:
			mach_write_ull(page_zip->data
				       + FIL_PAGE_LSN, newest_lsn);
			memset(page_zip->data + FIL_PAGE_FILE_FLUSH_LSN, 0, 8);
			mach_write_to_4(page_zip->data
					+ FIL_PAGE_SPACE_OR_CHKSUM,
					srv_use_checksums
					? page_zip_calc_checksum(
						page_zip->data, zip_size)
					: BUF_NO_CHECKSUM_MAGIC);
			return;
		}

		ut_error;
	}

	/* Write the newest modification lsn to the page header and trailer */
	mach_write_ull(page + FIL_PAGE_LSN, newest_lsn);

	mach_write_ull(page + UNIV_PAGE_SIZE - FIL_PAGE_END_LSN_OLD_CHKSUM,
		       newest_lsn);

	/* Store the new formula checksum */

	mach_write_to_4(page + FIL_PAGE_SPACE_OR_CHKSUM,
			srv_use_checksums
			? buf_calc_page_new_checksum(page)
			: BUF_NO_CHECKSUM_MAGIC);

	/* We overwrite the first 4 bytes of the end lsn field to store
	the old formula checksum. Since it depends also on the field
	FIL_PAGE_SPACE_OR_CHKSUM, it has to be calculated after storing the
	new formula checksum. */

	mach_write_to_4(page + UNIV_PAGE_SIZE - FIL_PAGE_END_LSN_OLD_CHKSUM,
			srv_use_checksums
			? buf_calc_page_old_checksum(page)
			: BUF_NO_CHECKSUM_MAGIC);
}

/************************************************************************
Does an asynchronous write of a buffer page. NOTE: in simulated aio and
also when the doublewrite buffer is used, we must call
buf_flush_buffered_writes after we have posted a batch of writes! */
static
void
buf_flush_write_block_low(
/*======================*/
	buf_block_t*	block)	/* in: buffer block to write */
{
#ifdef UNIV_LOG_DEBUG
	static ibool univ_log_debug_warned;
#endif /* UNIV_LOG_DEBUG */
	ut_a(buf_block_get_state(block) == BUF_BLOCK_FILE_PAGE);

#ifdef UNIV_IBUF_DEBUG
	ut_a(ibuf_count_get(buf_block_get_space(block),
			    buf_block_get_page_no(block)) == 0);
#endif
	ut_ad(block->page.newest_modification != 0);

#ifdef UNIV_LOG_DEBUG
	if (!univ_log_debug_warned) {
		univ_log_debug_warned = TRUE;
		fputs("Warning: cannot force log to disk if"
		      " UNIV_LOG_DEBUG is defined!\n"
		      "Crash recovery will not work!\n",
		      stderr);
	}
#else
	/* Force the log to the disk before writing the modified block */
	log_write_up_to(block->page.newest_modification,
			LOG_WAIT_ALL_GROUPS, TRUE);
#endif
	buf_flush_init_for_writing(block->frame,
				   buf_block_get_page_zip(block),
				   block->page.newest_modification);
	if (!srv_use_doublewrite_buf || !trx_doublewrite) {
		ulint	zip_size = buf_block_get_zip_size(block);

		fil_io(OS_FILE_WRITE | OS_AIO_SIMULATED_WAKE_LATER,
		       FALSE, buf_block_get_space(block), zip_size,
		       buf_block_get_page_no(block), 0,
		       zip_size ? zip_size : UNIV_PAGE_SIZE,
		       (void*)block->frame, (void*)block);
	} else {
		buf_flush_post_to_doublewrite_buf(block);
	}
}

/************************************************************************
Writes a page asynchronously from the buffer buf_pool to a file, if it can be
found in the buf_pool and it is in a flushable state. NOTE: in simulated aio
we must call os_aio_simulated_wake_handler_threads after we have posted a batch
of writes! */
static
ulint
buf_flush_try_page(
/*===============*/
					/* out: 1 if a page was
					flushed, 0 otherwise */
	ulint		space,		/* in: space id */
	ulint		offset,		/* in: page offset */
	enum buf_flush	flush_type)	/* in: BUF_FLUSH_LRU, BUF_FLUSH_LIST,
					or BUF_FLUSH_SINGLE_PAGE */
{
	buf_block_t*	block;
	ibool		locked;

	ut_ad(flush_type == BUF_FLUSH_LRU || flush_type == BUF_FLUSH_LIST
	      || flush_type == BUF_FLUSH_SINGLE_PAGE);

	mutex_enter(&(buf_pool->mutex));

	block = (buf_block_t*) buf_page_hash_get(space, offset);

	if (!block) {
		mutex_exit(&(buf_pool->mutex));
		return(0);
	}

	ut_a(buf_block_get_state(block) == BUF_BLOCK_FILE_PAGE); /* TODO */

	mutex_enter(&block->mutex);

	if (flush_type == BUF_FLUSH_LIST
	    && buf_flush_ready_for_flush(&block->page, flush_type)) {

		buf_block_set_io_fix(block, BUF_IO_WRITE);

		buf_page_set_flush_type(&block->page, flush_type);

		if (buf_pool->n_flush[flush_type] == 0) {

			os_event_reset(buf_pool->no_flush[flush_type]);
		}

		buf_pool->n_flush[flush_type]++;

		locked = FALSE;

		/* If the simulated aio thread is not running, we must
		not wait for any latch, as we may end up in a deadlock:
		if buf_fix_count == 0, then we know we need not wait */

		if (block->page.buf_fix_count == 0) {
			rw_lock_s_lock_gen(&(block->lock), BUF_IO_WRITE);

			locked = TRUE;
		}

		mutex_exit(&block->mutex);
		mutex_exit(&(buf_pool->mutex));

		if (!locked) {
			buf_flush_buffered_writes();

			rw_lock_s_lock_gen(&(block->lock), BUF_IO_WRITE);
		}

#ifdef UNIV_DEBUG
		if (buf_debug_prints) {
			fprintf(stderr,
				"Flushing page space %lu, page no %lu \n",
				(ulong) buf_block_get_space(block),
				(ulong) buf_block_get_page_no(block));
		}
#endif /* UNIV_DEBUG */

		buf_flush_write_block_low(block);

		return(1);

	} else if (flush_type == BUF_FLUSH_LRU
		   && buf_flush_ready_for_flush(&block->page, flush_type)) {

		/* VERY IMPORTANT:
		Because any thread may call the LRU flush, even when owning
		locks on pages, to avoid deadlocks, we must make sure that the
		s-lock is acquired on the page without waiting: this is
		accomplished because in the if-condition above we require
		the page not to be bufferfixed (in function
		..._ready_for_flush). */

		buf_block_set_io_fix(block, BUF_IO_WRITE);

		buf_page_set_flush_type(&block->page, flush_type);

		if (buf_pool->n_flush[flush_type] == 0) {

			os_event_reset(buf_pool->no_flush[flush_type]);
		}

		buf_pool->n_flush[flush_type]++;

		rw_lock_s_lock_gen(&(block->lock), BUF_IO_WRITE);

		/* Note that the s-latch is acquired before releasing the
		buf_pool mutex: this ensures that the latch is acquired
		immediately. */

		mutex_exit(&block->mutex);
		mutex_exit(&(buf_pool->mutex));

		buf_flush_write_block_low(block);

		return(1);

	} else if (flush_type == BUF_FLUSH_SINGLE_PAGE
		   && buf_flush_ready_for_flush(&block->page, flush_type)) {

		buf_block_set_io_fix(block, BUF_IO_WRITE);

		buf_page_set_flush_type(&block->page, flush_type);

		if (buf_pool->n_flush[flush_type] == 0) {

			os_event_reset(buf_pool->no_flush[flush_type]);
		}

		buf_pool->n_flush[flush_type]++;

		mutex_exit(&block->mutex);
		mutex_exit(&(buf_pool->mutex));

		rw_lock_s_lock_gen(&(block->lock), BUF_IO_WRITE);

#ifdef UNIV_DEBUG
		if (buf_debug_prints) {
			fprintf(stderr,
				"Flushing single page space %lu,"
				" page no %lu \n",
				(ulong) buf_block_get_space(block),
				(ulong) buf_block_get_page_no(block));
		}
#endif /* UNIV_DEBUG */

		buf_flush_write_block_low(block);

		return(1);
	}

	mutex_exit(&block->mutex);
	mutex_exit(&(buf_pool->mutex));

	return(0);
}

/***************************************************************
Flushes to disk all flushable pages within the flush area. */
static
ulint
buf_flush_try_neighbors(
/*====================*/
					/* out: number of pages flushed */
	ulint		space,		/* in: space id */
	ulint		offset,		/* in: page offset */
	enum buf_flush	flush_type)	/* in: BUF_FLUSH_LRU or
					BUF_FLUSH_LIST */
{
	buf_page_t*	bpage;
	ulint		low, high;
	ulint		count		= 0;
	ulint		i;

	ut_ad(flush_type == BUF_FLUSH_LRU || flush_type == BUF_FLUSH_LIST);

	low = (offset / BUF_FLUSH_AREA) * BUF_FLUSH_AREA;
	high = (offset / BUF_FLUSH_AREA + 1) * BUF_FLUSH_AREA;

	if (UT_LIST_GET_LEN(buf_pool->LRU) < BUF_LRU_OLD_MIN_LEN) {
		/* If there is little space, it is better not to flush any
		block except from the end of the LRU list */

		low = offset;
		high = offset + 1;
	}

	/* fprintf(stderr, "Flush area: low %lu high %lu\n", low, high); */

	if (high > fil_space_get_size(space)) {
		high = fil_space_get_size(space);
	}

	mutex_enter(&(buf_pool->mutex));

	for (i = low; i < high; i++) {

		bpage = buf_page_hash_get(space, i);
		ut_a(!bpage || buf_page_in_file(bpage));

		if (!bpage) {

			continue;

		} else if (flush_type == BUF_FLUSH_LRU && i != offset
			   && !buf_page_is_old(bpage)) {

			/* We avoid flushing 'non-old' blocks in an LRU flush,
			because the flushed blocks are soon freed */

			continue;
		} else {

			mutex_t* block_mutex = buf_page_get_mutex(bpage);

			mutex_enter(block_mutex);

			if (buf_flush_ready_for_flush(bpage, flush_type)
			    && (i == offset || !bpage->buf_fix_count)) {
				/* We only try to flush those
				neighbors != offset where the buf fix count is
				zero, as we then know that we probably can
				latch the page without a semaphore wait.
				Semaphore waits are expensive because we must
				flush the doublewrite buffer before we start
				waiting. */

				mutex_exit(&(buf_pool->mutex));

				mutex_exit(block_mutex);

				/* Note: as we release the buf_pool mutex
				above, in buf_flush_try_page we cannot be sure
				the page is still in a flushable state:
				therefore we check it again inside that
				function. */

				count += buf_flush_try_page(space, i,
							    flush_type);

				mutex_enter(&(buf_pool->mutex));
			} else {
				mutex_exit(block_mutex);
			}
		}
	}

	mutex_exit(&(buf_pool->mutex));

	return(count);
}

/***********************************************************************
This utility flushes dirty blocks from the end of the LRU list or flush_list.
NOTE 1: in the case of an LRU flush the calling thread may own latches to
pages: to avoid deadlocks, this function must be written so that it cannot
end up waiting for these latches! NOTE 2: in the case of a flush list flush,
the calling thread is not allowed to own any latches on pages! */

ulint
buf_flush_batch(
/*============*/
					/* out: number of blocks for which the
					write request was queued;
					ULINT_UNDEFINED if there was a flush
					of the same type already running */
	enum buf_flush	flush_type,	/* in: BUF_FLUSH_LRU or
					BUF_FLUSH_LIST; if BUF_FLUSH_LIST,
					then the caller must not own any
					latches on pages */
	ulint		min_n,		/* in: wished minimum mumber of blocks
					flushed (it is not guaranteed that the
					actual number is that big, though) */
	ib_uint64_t	lsn_limit)	/* in the case BUF_FLUSH_LIST all
					blocks whose oldest_modification is
					smaller than this should be flushed
					(if their number does not exceed
					min_n), otherwise ignored */
{
	buf_page_t*	bpage;
	ulint		page_count	= 0;
	ulint		old_page_count;
	ulint		space;
	ulint		offset;
	ibool		found;

	ut_ad((flush_type == BUF_FLUSH_LRU)
	      || (flush_type == BUF_FLUSH_LIST));
#ifdef UNIV_SYNC_DEBUG
	ut_ad((flush_type != BUF_FLUSH_LIST)
	      || sync_thread_levels_empty_gen(TRUE));
#endif /* UNIV_SYNC_DEBUG */
	mutex_enter(&(buf_pool->mutex));

	if ((buf_pool->n_flush[flush_type] > 0)
	    || (buf_pool->init_flush[flush_type] == TRUE)) {

		/* There is already a flush batch of the same type running */

		mutex_exit(&(buf_pool->mutex));

		return(ULINT_UNDEFINED);
	}

	buf_pool->init_flush[flush_type] = TRUE;

	for (;;) {
		/* If we have flushed enough, leave the loop */
		if (page_count >= min_n) {

			break;
		}

		/* Start from the end of the list looking for a suitable
		block to be flushed. */

		if (flush_type == BUF_FLUSH_LRU) {
			bpage = UT_LIST_GET_LAST(buf_pool->LRU);
		} else {
			ut_ad(flush_type == BUF_FLUSH_LIST);

			bpage = UT_LIST_GET_LAST(buf_pool->flush_list);
			if (!bpage
			    || bpage->oldest_modification >= lsn_limit) {
				/* We have flushed enough */

				break;
			}
		}

		found = FALSE;

		/* Note that after finding a single flushable page, we try to
		flush also all its neighbors, and after that start from the
		END of the LRU list or flush list again: the list may change
		during the flushing and we cannot safely preserve within this
		function a pointer to a block in the list! */

		while ((bpage != NULL) && !found) {
			mutex_t* block_mutex = buf_page_get_mutex(bpage);

			ut_a(buf_page_in_file(bpage));

			mutex_enter(block_mutex);

			if (buf_flush_ready_for_flush(bpage, flush_type)) {

				found = TRUE;
				space = buf_page_get_space(bpage);
				offset = buf_page_get_page_no(bpage);

				mutex_exit(&(buf_pool->mutex));
				mutex_exit(block_mutex);

				old_page_count = page_count;

				/* Try to flush also all the neighbors */
				page_count += buf_flush_try_neighbors(
					space, offset, flush_type);
				/* fprintf(stderr,
				"Flush type %lu, page no %lu, neighb %lu\n",
				flush_type, offset,
				page_count - old_page_count); */

				mutex_enter(&(buf_pool->mutex));

			} else if (flush_type == BUF_FLUSH_LRU) {

				mutex_exit(block_mutex);

				bpage = UT_LIST_GET_PREV(LRU, bpage);
			} else {
				ut_ad(flush_type == BUF_FLUSH_LIST);

				mutex_exit(block_mutex);

				bpage = UT_LIST_GET_PREV(free_or_flush_list,
							 bpage);
			}
		}

		/* If we could not find anything to flush, leave the loop */

		if (!found) {
			break;
		}
	}

	buf_pool->init_flush[flush_type] = FALSE;

	if ((buf_pool->n_flush[flush_type] == 0)
	    && (buf_pool->init_flush[flush_type] == FALSE)) {

		/* The running flush batch has ended */

		os_event_set(buf_pool->no_flush[flush_type]);
	}

	mutex_exit(&(buf_pool->mutex));

	buf_flush_buffered_writes();

#ifdef UNIV_DEBUG
	if (buf_debug_prints && page_count > 0) {
		ut_a(flush_type == BUF_FLUSH_LRU
		     || flush_type == BUF_FLUSH_LIST);
		fprintf(stderr, flush_type == BUF_FLUSH_LRU
			? "Flushed %lu pages in LRU flush\n"
			: "Flushed %lu pages in flush list flush\n",
			(ulong) page_count);
	}
#endif /* UNIV_DEBUG */

	if (page_count != ULINT_UNDEFINED) {
		srv_buf_pool_flushed += page_count;
	}

	return(page_count);
}

/**********************************************************************
Waits until a flush batch of the given type ends */

void
buf_flush_wait_batch_end(
/*=====================*/
	enum buf_flush	type)	/* in: BUF_FLUSH_LRU or BUF_FLUSH_LIST */
{
	ut_ad((type == BUF_FLUSH_LRU) || (type == BUF_FLUSH_LIST));

	os_event_wait(buf_pool->no_flush[type]);
}

/**********************************************************************
Gives a recommendation of how many blocks should be flushed to establish
a big enough margin of replaceable blocks near the end of the LRU list
and in the free list. */
static
ulint
buf_flush_LRU_recommendation(void)
/*==============================*/
			/* out: number of blocks which should be flushed
			from the end of the LRU list */
{
	buf_page_t*	bpage;
	ulint		n_replaceable;
	ulint		distance	= 0;

	mutex_enter(&(buf_pool->mutex));

	n_replaceable = UT_LIST_GET_LEN(buf_pool->free);

	bpage = UT_LIST_GET_LAST(buf_pool->LRU);

	while ((bpage != NULL)
	       && (n_replaceable < BUF_FLUSH_FREE_BLOCK_MARGIN
		   + BUF_FLUSH_EXTRA_MARGIN)
	       && (distance < BUF_LRU_FREE_SEARCH_LEN)) {

		mutex_t* block_mutex = buf_page_get_mutex(bpage);

		mutex_enter(block_mutex);

		if (buf_flush_ready_for_replace(bpage)) {
			n_replaceable++;
		}

		mutex_exit(block_mutex);

		distance++;

		bpage = UT_LIST_GET_PREV(LRU, bpage);
	}

	mutex_exit(&(buf_pool->mutex));

	if (n_replaceable >= BUF_FLUSH_FREE_BLOCK_MARGIN) {

		return(0);
	}

	return(BUF_FLUSH_FREE_BLOCK_MARGIN + BUF_FLUSH_EXTRA_MARGIN
	       - n_replaceable);
}

/*************************************************************************
Flushes pages from the end of the LRU list if there is too small a margin
of replaceable pages there or in the free list. VERY IMPORTANT: this function
is called also by threads which have locks on pages. To avoid deadlocks, we
flush only pages such that the s-lock required for flushing can be acquired
immediately, without waiting. */

void
buf_flush_free_margin(void)
/*=======================*/
{
	ulint	n_to_flush;
	ulint	n_flushed;

	n_to_flush = buf_flush_LRU_recommendation();

	if (n_to_flush > 0) {
		n_flushed = buf_flush_batch(BUF_FLUSH_LRU, n_to_flush, 0);
		if (n_flushed == ULINT_UNDEFINED) {
			/* There was an LRU type flush batch already running;
			let us wait for it to end */

			buf_flush_wait_batch_end(BUF_FLUSH_LRU);
		}
	}
}

#if defined UNIV_DEBUG || defined UNIV_BUF_DEBUG
/**********************************************************************
Validates the flush list. */
static
ibool
buf_flush_validate_low(void)
/*========================*/
		/* out: TRUE if ok */
{
	buf_page_t*	bpage;
	ib_uint64_t	om;

	UT_LIST_VALIDATE(free_or_flush_list, buf_page_t, buf_pool->flush_list);

	bpage = UT_LIST_GET_FIRST(buf_pool->flush_list);

	while (bpage != NULL) {
		om = bpage->oldest_modification;
		ut_a(buf_page_in_file(bpage));
		ut_a(om > 0);

		bpage = UT_LIST_GET_NEXT(free_or_flush_list, bpage);

		if (bpage) {
			ut_a(om >= bpage->oldest_modification);
		}
	}

	return(TRUE);
}

/**********************************************************************
Validates the flush list. */

ibool
buf_flush_validate(void)
/*====================*/
		/* out: TRUE if ok */
{
	ibool	ret;

	mutex_enter(&(buf_pool->mutex));

	ret = buf_flush_validate_low();

	mutex_exit(&(buf_pool->mutex));

	return(ret);
}
#endif /* UNIV_DEBUG || UNIV_BUF_DEBUG */
