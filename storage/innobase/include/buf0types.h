/*****************************************************************************

Copyright (c) 1995, 2011, Oracle and/or its affiliates. All Rights Reserved

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; version 2 of the License.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program; if not, write to the Free Software Foundation, Inc., 59 Temple
Place, Suite 330, Boston, MA 02111-1307 USA

*****************************************************************************/

/**************************************************//**
@file include/buf0types.h
The database buffer pool global types for the directory

Created 11/17/1995 Heikki Tuuri
*******************************************************/

#ifndef buf0types_h
#define buf0types_h

/** Buffer page (uncompressed or compressed) */
typedef	struct buf_page_struct		buf_page_t;
/** Buffer block for which an uncompressed page exists */
typedef	struct buf_block_struct		buf_block_t;
/** Buffer pool chunk comprising buf_block_t */
typedef struct buf_chunk_struct		buf_chunk_t;
/** Buffer pool comprising buf_chunk_t */
typedef	struct buf_pool_struct		buf_pool_t;
/** Buffer pool statistics struct */
typedef	struct buf_pool_stat_struct	buf_pool_stat_t;
/** Buffer pool buddy statistics struct */
typedef	struct buf_buddy_stat_struct	buf_buddy_stat_t;

/** A buffer frame. @see page_t */
typedef	byte	buf_frame_t;

/** Flags for flush types */
enum buf_flush {
	BUF_FLUSH_LRU = 0,		/*!< flush via the LRU list */
	BUF_FLUSH_LIST,			/*!< flush via the flush list
					of dirty blocks */
	BUF_FLUSH_SINGLE_PAGE,		/*!< flush via the LRU list
					but only a single page */
	BUF_FLUSH_N_TYPES		/*!< index of last element + 1  */
};

/** Flags for io_fix types */
enum buf_io_fix {
	BUF_IO_NONE = 0,		/**< no pending I/O */
	BUF_IO_READ,			/**< read pending */
	BUF_IO_WRITE,			/**< write pending */
	BUF_IO_PIN			/**< disallow relocation of
					block and its removal of from
					the flush_list */
};

/** Alternatives for srv_checksum_algorithm, which can be changed by
setting innodb_checksum_algorithm */
enum srv_checksum_algorithm_enum {
	SRV_CHECKSUM_ALGORITHM_CRC32,		/*!< Write crc32, allow crc32,
						innodb or none when reading */
	SRV_CHECKSUM_ALGORITHM_STRICT_CRC32,	/*!< Write crc32, allow crc32
						when reading */
	SRV_CHECKSUM_ALGORITHM_INNODB,		/*!< Write innodb, allow crc32,
						innodb or none when reading */
	SRV_CHECKSUM_ALGORITHM_STRICT_INNODB,	/*!< Write innodb, allow
						innodb when reading */
	SRV_CHECKSUM_ALGORITHM_NONE,		/*!< Write none, allow crc32,
						innodb or none when reading */
	SRV_CHECKSUM_ALGORITHM_STRICT_NONE,	/*!< Write none, allow none
						when reading */
};

typedef enum srv_checksum_algorithm_enum	srv_checksum_algorithm_t;

/** Parameters of binary buddy system for compressed pages (buf0buddy.h) */
/* @{ */
/** Zip shift value for the smallest page size */
#define BUF_BUDDY_LOW_SHIFT	UNIV_ZIP_SIZE_SHIFT_MIN

/** Smallest buddy page size */
#define BUF_BUDDY_LOW		(1U << BUF_BUDDY_LOW_SHIFT)

/** Actual number of buddy sizes based on current page size */
#define BUF_BUDDY_SIZES		(UNIV_PAGE_SIZE_SHIFT - BUF_BUDDY_LOW_SHIFT)

/** Maximum number of buddy sizes based on the max page size */
#define BUF_BUDDY_SIZES_MAX	(UNIV_PAGE_SIZE_SHIFT_MAX	\
				- BUF_BUDDY_LOW_SHIFT)

/** twice the maximum block size of the buddy system;
the underlying memory is aligned by this amount:
this must be equal to UNIV_PAGE_SIZE */
#define BUF_BUDDY_HIGH	(BUF_BUDDY_LOW << BUF_BUDDY_SIZES)
/* @} */

#endif

