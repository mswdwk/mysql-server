/* Copyright (c) 2000, 2017, Oracle and/or its affiliates. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA
 */

/**
 * @file mysys/my_alloc.cc
 * Implementation of MEM_ROOT.
 *
 * This file follows Google coding style.
 */

#include <stdarg.h>
#include <string.h>
#include <sys/types.h>

#include "my_alloc.h"
#include "my_compiler.h"
#include "my_dbug.h"
#include "my_inttypes.h"
#include "my_pointer_arithmetic.h"
#include "my_sys.h"
#include "mysql/service_mysql_alloc.h"
#include "mysys_err.h"
#include "template_utils.h"

// For instrumented code: Always use malloc(); never reuse a chunk.
// This gives a lot more memory chunks, each with a red-zone around them.
#if defined(HAVE_VALGRIND) || defined(HAVE_ASAN)
#define MEM_ROOT_SINGLE_CHUNKS 1
#else
#define MEM_ROOT_SINGLE_CHUNKS 0
#endif

MEM_ROOT::Block *MEM_ROOT::AllocBlock(size_t length) {
  DBUG_ENTER("MEM_ROOT::AllocBlock");

  if (m_max_capacity != 0 &&
      (m_allocated_size > m_max_capacity ||
       length > m_max_capacity - m_allocated_size)) {
    if (m_error_for_capacity_exceeded) {
      my_error(EE_CAPACITY_EXCEEDED, MYF(0),
               static_cast<ulonglong>(m_max_capacity));
      // NOTE: No early return; we will abort the query at the next safe point.
    } else {
      DBUG_RETURN(nullptr);
    }
  }

  Block *new_block = static_cast<Block *>(my_malloc(
      m_psi_key, length + sizeof(Block), MYF(MY_WME | ME_FATALERROR)));
  if (new_block == nullptr) {
    if (m_error_handler) (m_error_handler)();
    DBUG_RETURN(nullptr);
  }

  m_allocated_size += length;

  // Make the default block size 50% larger next time.
  // This ensures O(1) total mallocs (assuming Clear() is not called).
  m_block_size += m_block_size / 2;
  DBUG_RETURN(new_block);
}

void *MEM_ROOT::AllocSlow(size_t length) {
  DBUG_ENTER("MEM_ROOT::alloc");
  DBUG_PRINT("enter", ("root: %p", this));

  // We need to allocate a new block to satisfy this allocation;
  // otherwise, the fast path in Alloc() would not have sent us here.
  // We plan to allocate a block of <block_size> bytes; see if that
  // would be enough or not.
  if (length >= m_block_size || MEM_ROOT_SINGLE_CHUNKS) {
    // The next block we'd allocate would _not_ be big enough
    // (or we're in Valgrind/ASAN mode, and want everything in single chunks).
    // Allocate an entirely new block, not disturbing anything;
    // since the new block isn't going to be used for the next allocation
    // anyway, we can just as well keep the previous one.
    Block *new_block = AllocBlock(length);
    if (new_block == nullptr) DBUG_RETURN(nullptr);

    if (m_current_block == nullptr) {
      // This is the only block, so it has to be the current block, too.
      // However, it will be full, so we won't be allocating from it
      // unless ClearForReuse() is called.
      new_block->prev = nullptr;
      m_current_block = new_block;
      m_current_free_end = pointer_cast<char *>(new_block) +
          sizeof(*new_block) + length;
      m_current_free_start = m_current_free_end;
    } else {
      // Insert the new block in the second-to-last position.
      new_block->prev = m_current_block->prev;
      m_current_block->prev = new_block;
    }

    DBUG_RETURN(pointer_cast<char *>(new_block) + sizeof(*new_block));
  } else {
    // The normal case: Throw away the current block, allocate a new block,
    // and use that to satisfy the new allocation.
    const size_t new_block_size = m_block_size;
    Block *new_block = AllocBlock(new_block_size);  // Will modify block_size.
    if (new_block == nullptr) DBUG_RETURN(nullptr);

    new_block->prev = m_current_block;
    m_current_block = new_block;

    char *new_mem = pointer_cast<char *>(new_block) + sizeof(*new_block);
    m_current_free_start = new_mem + length;
    m_current_free_end = new_mem + new_block_size;
    DBUG_RETURN(new_mem);
  }
}

void MEM_ROOT::Clear() {
  DBUG_ENTER("MEM_ROOT::Clear()");
  DBUG_PRINT("enter", ("root: %p", this));

  // Already cleared, or memset() to zero, so just ignore.
  if (m_current_block == nullptr) DBUG_VOID_RETURN;

  Block *start = m_current_block;

  m_current_block = nullptr;
  m_block_size = m_orig_block_size;
  m_current_free_start = &s_dummy_target;
  m_current_free_end = &s_dummy_target;
  m_allocated_size = 0;

  FreeBlocks(start);
  DBUG_VOID_RETURN;
}

void MEM_ROOT::ClearForReuse() {
  DBUG_ENTER("MEM_ROOT::ClearForReuse()");

  if (MEM_ROOT_SINGLE_CHUNKS) {
    Clear();
    DBUG_VOID_RETURN;
  }

  // Already cleared, or memset() to zero, so just ignore.
  if (m_current_block == nullptr) DBUG_VOID_RETURN;

  // Keep the last block, which is usually the biggest one.
  m_current_free_start =
      pointer_cast<char *>(m_current_block) + sizeof(*m_current_block);
  Block *start = m_current_block->prev;
  m_current_block->prev = nullptr;
  m_allocated_size = m_current_free_end - m_current_free_start;

  FreeBlocks(start);
  DBUG_VOID_RETURN;
}

void MEM_ROOT::FreeBlocks(Block *start) {
  // The MEM_ROOT might be allocated on itself, so make sure we don't
  // touch it after we've started freeing.
  for (Block *block = start; block != nullptr;) {
    Block *prev = block->prev;
    my_free(block);
    block = prev;
  }
}

void MEM_ROOT::Claim() {
  DBUG_ENTER("MEM_ROOT::Claim()");
  DBUG_PRINT("enter", ("root: %p", this));

  for (Block *block = m_current_block; block != nullptr; block = block->prev) {
    my_claim(block);
  }

  DBUG_VOID_RETURN;
}

/*
 * Allocate many pointers at the same time.
 *
 * DESCRIPTION
 *   ptr1, ptr2, etc all point into big allocated memory area.
 *
 * SYNOPSIS
 *   multi_alloc_root()
 *     root               Memory root
 *     ptr1, length1      Multiple arguments terminated by a NULL pointer
 *     ptr2, length2      ...
 *     ...
 *     NULL
 *
 * RETURN VALUE
 *   A pointer to the beginning of the allocated memory block
 *   in case of success or NULL if out of memory.
 */

void *multi_alloc_root(MEM_ROOT *root, ...) {
  va_list args;
  char **ptr, *start, *res;
  size_t tot_length, length;
  DBUG_ENTER("multi_alloc_root");

  va_start(args, root);
  tot_length = 0;
  while ((ptr = va_arg(args, char **))) {
    length = va_arg(args, uint);
    tot_length += ALIGN_SIZE(length);
  }
  va_end(args);

  if (!(start = static_cast<char *>(alloc_root(root, tot_length))))
    DBUG_RETURN(0); /* purecov: inspected */

  va_start(args, root);
  res = start;
  while ((ptr = va_arg(args, char **))) {
    *ptr = res;
    length = va_arg(args, uint);
    res += ALIGN_SIZE(length);
  }
  va_end(args);
  DBUG_RETURN((void *)start);
}

extern "C" char *strdup_root(MEM_ROOT *root, const char *str) {
  return strmake_root(root, str, strlen(str));
}

extern "C" char *safe_strdup_root(MEM_ROOT *root, const char *str) {
  return str ? strdup_root(root, str) : 0;
}

void free_root(MEM_ROOT *root, myf flags) {
  if (root != nullptr) {
    if ((flags & MY_MARK_BLOCKS_FREE) || (flags & MY_KEEP_PREALLOC))
      root->ClearForReuse();
    else
      root->Clear();
  }
}

char *strmake_root(MEM_ROOT *root, const char *str, size_t len) {
  char *pos;
  if ((pos = static_cast<char *>(alloc_root(root, len + 1)))) {
    if (len > 0) memcpy(pos, str, len);
    pos[len] = 0;
  }
  return pos;
}

void *memdup_root(MEM_ROOT *root, const void *str, size_t len) {
  char *pos;
  if ((pos = static_cast<char *>(alloc_root(root, len)))) {
    memcpy(pos, str, len);
  }
  return pos;
}

char MEM_ROOT::s_dummy_target;
