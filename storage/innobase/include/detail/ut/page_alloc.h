/*****************************************************************************

Copyright (c) 2021, Oracle and/or its affiliates.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License, version 2.0, as published by the
Free Software Foundation.

This program is also distributed with certain software (including but not
limited to OpenSSL) that is licensed under separate terms, as designated in a
particular file or component or in included license documentation. The authors
of MySQL hereby grant you an additional permission to link the program and
your derivative works with the separately licensed software that they have
included with MySQL.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License, version 2.0,
for more details.

You should have received a copy of the GNU General Public License along with
this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA

*****************************************************************************/

/** @file include/detail/ut/page_alloc.h
 Implementation bits and pieces for page-aligned allocations. */

#ifndef detail_ut_page_alloc_h
#define detail_ut_page_alloc_h

#ifdef _WIN32
#include <windows.h>
// _must_ go after windows.h
#include <memoryapi.h>
#else
#include <sys/mman.h>
#endif

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <utility>

#include "my_compiler.h"
#include "storage/innobase/include/detail/ut/allocator_traits.h"
#include "storage/innobase/include/detail/ut/pfs.h"

namespace ut {
namespace detail {

/** Allocates system page-aligned memory.

    @param[in] n_bytes Size of storage (in bytes) requested to be allocated.
    @return Pointer to the allocated storage. nullptr if allocation failed.
*/
inline void *page_aligned_alloc(size_t n_bytes) {
#ifdef _WIN32
  // With lpAddress set to nullptr, VirtualAlloc will internally round n_bytes
  // to the multiple of system page size if it is not already
  void *ptr =
      VirtualAlloc(nullptr, n_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  return ptr;
#else
  // With addr set to nullptr, mmap will internally round n_bytes to the
  // multiple of system page size if it is not already
  void *ptr = mmap(nullptr, n_bytes, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON, -1, 0);
  return (ptr != (void *)-1) ? ptr : nullptr;
#endif
}

/** Releases system page-aligned storage.

    @param[in] ptr Pointer to system page-aligned storage.
    @param[in] n_bytes Size of the storage.
 */
inline void page_aligned_free(void *ptr, size_t n_bytes) {
  if (unlikely(!ptr)) return;
#ifdef _WIN32
  VirtualFree(ptr, 0, MEM_RELEASE);
  (void)n_bytes;
#else
  // length aka n_bytes needs not to be aligned to page-size
  munmap(ptr, n_bytes);
#endif
}

/** Allocation routines which are purposed for allocating system page-aligned
    memory.

    page_aligned_alloc() and page_aligned_free() are taking care of
    OS specific details and Page_alloc is a convenience wrapper which only
    makes the use of system page-aligned memory more ergonomic so that it
    serializes the actual size being allocated into the raw memory. This size
    is then automagically deduced when system page-aligned memory is being
    freed. Otherwise, client code would have been responsible to store and keep
    that value somewhere until the memory segment is freed.

    Memory layout representation looks like the following:

     ---------------------------------------
     | SYSTEM-PAGE-META |   ... DATA ...   |
     ---------------------------------------
       ^                 ^
       |                 |
       |                 |
       |                ptr (system-page) to be returned to call-site
       |
      -------------------
      |    DATALEN      |
      -------------------
       \                \
        0                \
                   CPU_PAGE_SIZE - 1

    DATA is an actual page-aligned segment that will be returned to the
    call-site and which the client code will be able to use for the application
    data.
 */
struct Page_alloc : public allocator_traits<false> {
  /** This is how much the metadata (SYSTEM-PAGE-META) segment will be big. */
  static constexpr auto metadata_len = CPU_PAGE_SIZE;

  /** This is the type we will be using to store the size of successful
      system-page allocation size.
    */
  using datalen_t = size_t;

  /** Sanity check so that we can be sure that the size of our metadata segment
      is such so that the pointer to DATA segment is always suitably aligned
      (multiple of alignof(max_align_t).
    */
  static_assert(metadata_len % alignof(max_align_t) == 0,
                "metadata_len must be divisible by alignof(max_align_t)");

  /** Sanity check so that we can be sure that our metadata segment can fit
      the datalen_t.
    */
  static_assert(sizeof(datalen_t) <= metadata_len, "Metadata does not fit!");

  /** Allocates system page-aligned memory.

      @param[in] size Size of storage (in bytes) requested to be allocated.
      @return Pointer to the allocated storage. nullptr if allocation failed.
   */
  static inline void *alloc(std::size_t size) {
    auto total_len = size + Page_alloc::metadata_len;
    auto mem = page_aligned_alloc(total_len);
    if (unlikely(!mem)) return nullptr;
    *reinterpret_cast<datalen_t *>(mem) = total_len;
    return static_cast<uint8_t *>(mem) + Page_alloc::metadata_len;
  }

  /** Releases storage allocated through Page_alloc::alloc().

      @param[in] data Pointer to storage allocated through
      Page_alloc::alloc()
   */
  static inline void free(void *data) noexcept {
    if (unlikely(!data)) return;
    page_aligned_free(deduce(data), datalen(data) + Page_alloc::metadata_len);
  }

  /** Returns the number of bytes that have been allocated.

      @param[in] data Pointer to storage allocated through
      Page_alloc::alloc()
      @return Number of bytes.
   */
  static inline datalen_t datalen(void *data) {
    return *reinterpret_cast<datalen_t *>(static_cast<uint8_t *>(data) -
                                          Page_alloc::metadata_len);
  }

 private:
  /** Helper function which deduces the original pointer returned by
      Page_alloc from a pointer which is passed to us by the call-site.
   */
  static inline void *deduce(void *data) noexcept {
    return reinterpret_cast<void *>(static_cast<uint8_t *>(data) -
                                    Page_alloc::metadata_len);
  }
};

/** Allocation routines which are purposed for allocating system page-aligned
    memory. This is a PFS (performance-schema) variant of Page_alloc.
    Implemented in terms of PFS_metadata.

    page_aligned_alloc() and page_aligned_free() are taking care of
    OS specific details and Page_alloc_pfs is a convenience wrapper which
    only makes the use of system page-aligned memory more ergonomic so that
    it serializes all the relevant PFS details into the raw memory. Otherwise,
    client code would have been responsible to store and keep those details
    somewhere until the memory segment is freed.

    Memory layout representation looks like the following:

     --------------------------------------------------
     | PFS-META | VARLEN | PFS-META-OFFSET |   DATA   |
     --------------------------------------------------
      ^    ^                                ^
      |    |                                |
      |   ---------------------------       |
      |   | OWNER |  DATALEN  | KEY |       |
      |   ---------------------------       |
      |                                     |
     ptr returned by                        |
     page_aligned_alloc                     |
                                            |
                        ptr (system-page) to be returned to call-site
                                   will be pointing here

    OWNER field encodes the owning thread.
    DATALEN field encodes total size of memory consumed and not only the size of
    the DATA segment.
    KEY field encodes the PFS/PSI key.

    VARLEN is the leftover variable-length segment that specialized
    implementations can further make use of by deducing its size from the
    following formulae: abs(CPU_PAGE_SIZE - sizeof(PFS-META-OFFSET) -
    sizeof(PFS-META)). In code that would be std::abs(CPU_PAGE_SIZE -
    PFS_metadata::pfs_metadata_size). Not used by this implementation.

    PFS-META-OFFSET, strictly speaking, isn't neccesary in this case of
    system-pages, where alignment is always known in compile-time and thus the
    offset we will be storing into the PFS-META-OFFSET field is always going
    to be the same for the given platform. So, rather than serializing this
    piece of information into the memory as we do right now, we could very
    well be storing it into the compile-time evaluated constexpr constant. The
    reason why we don't do it is that there is no advantage (*) of doing so
    while we would be introducing a disadvantage of having to maintain separate
    specialization of PFS_metadata and code would be somewhat more fragmented.

      (*) Extra space that we need to allocate in order to be able to fit the
          PFS_metadata is going to be the same regardless if there is
          PFS-META-OFFSET field or not. This is due to the fact that PFS-META
          segment alone is larger than alignof(max_align_t) so in order to
          keep the DATA segment suitably aligned (% alignof(max_align_t) == 0)
          we must choose the size for the whole PFS segment that is a multiple
          of alignof(max_align_t).

    PFS-META-OFFSET is a field which allows us to recover the pointer to
    PFS-META segment from a pointer to DATA segment.

    DATA is an actual page-aligned segment that will be returned to the
    call-site and which the client code will be able to use for the application
    data.
 */
struct Page_alloc_pfs : public allocator_traits<true> {
  using pfs_metadata = PFS_metadata;

  /** This is how much the metadata (PFS-META | VARLEN | PFS-META-OFFSET)
      segment will be big.
    */
  static constexpr auto metadata_len = CPU_PAGE_SIZE;

  /** Sanity check so that we can be sure that the size of our metadata segment
      is such so that the pointer to DATA segment is always suitably aligned
      (multiple of alignof(max_align_t).
    */
  static_assert(metadata_len % alignof(max_align_t) == 0,
                "metadata_len must be divisible by alignof(max_align_t)");

  /** Allocates system page-aligned memory.

      @param[in] size Size of storage (in bytes) requested to be allocated.
      @param[in] key PSI memory key to be used for PFS memory instrumentation.
      @return Pointer to the allocated storage. nullptr if allocation failed.
    */
  static inline void *alloc(std::size_t size,
                            pfs_metadata::pfs_memory_key_t key) {
    auto total_len = size + Page_alloc_pfs::metadata_len;
    auto mem = page_aligned_alloc(total_len);
    if (unlikely(!mem)) return nullptr;

#ifdef HAVE_PSI_MEMORY_INTERFACE
    // The point of this allocator variant is to trace the memory allocations
    // through PFS (PSI) so do it.
    pfs_metadata::pfs_owning_thread_t owner;
    key = PSI_MEMORY_CALL(memory_alloc)(key, total_len, &owner);
    // To be able to do the opposite action of tracing when we are releasing the
    // memory, we need right about the same data we passed to the tracing
    // memory_alloc function. Let's encode this it into our allocator so we
    // don't have to carry and keep this data around.
    pfs_metadata::pfs_owning_thread(mem, owner);
    pfs_metadata::pfs_datalen(mem, total_len);
    pfs_metadata::pfs_key(mem, key);
    pfs_metadata::pfs_metaoffset(mem, Page_alloc_pfs::metadata_len);
#endif

    return static_cast<uint8_t *>(mem) + Page_alloc_pfs::metadata_len;
  }

  /** Releases storage allocated through Page_alloc_pfs::alloc().

      @param[in] data Pointer to storage allocated through
      Page_alloc_pfs::alloc()
   */
  static inline void free(PFS_metadata::data_segment_ptr data) noexcept {
    if (unlikely(!data)) return;

#ifdef HAVE_PSI_MEMORY_INTERFACE
    // Deduce the PFS data we encoded in Page_alloc_pfs::alloc()
    auto key = pfs_metadata::pfs_key(data);
    auto owner = pfs_metadata::pfs_owning_thread(data);
    auto total_len = pfs_metadata::pfs_datalen(data);
    // With the deduced PFS data, now trace the memory release action.
    PSI_MEMORY_CALL(memory_free)
    (key, total_len, owner);

    page_aligned_free(deduce(data), total_len);
#endif
  }

  /** Returns the number of bytes that have been allocated.

      @param[in] data Pointer to storage allocated through
      Page_alloc_pfs::alloc()
      @return Number of bytes.
   */
  static inline size_t datalen(PFS_metadata::data_segment_ptr data) {
    return pfs_metadata::pfs_datalen(data) - Page_alloc_pfs::metadata_len;
  }

 private:
  /** Helper function which deduces the original pointer returned by
      Page_alloc_pfs from a pointer which is passed to us by the
      call-site.
   */
  static inline void *deduce(PFS_metadata::data_segment_ptr data) noexcept {
    return pfs_metadata::deduce_pfs_meta(data);
  }
};

/** Simple utility metafunction which selects appropriate allocator variant
    (implementation) depending on the input parameter(s).
  */
template <bool Pfs_memory_instrumentation_on>
struct select_page_alloc_impl {
  using type = Page_alloc;  // When PFS is OFF, pick ordinary, non-PFS, variant
};

template <>
struct select_page_alloc_impl<true> {
  using type = Page_alloc_pfs;  // Otherwise, pick PFS variant
};

/** Just a small helper type which saves us some keystrokes. */
template <bool Pfs_memory_instrumentation_on>
using select_page_alloc_impl_t =
    typename select_page_alloc_impl<Pfs_memory_instrumentation_on>::type;

/** Small wrapper which utilizes SFINAE to dispatch the call to appropriate
    aligned allocator implementation.
  */
template <typename Impl>
struct Page_alloc_ {
  template <typename T = Impl>
  static inline typename std::enable_if<T::is_pfs_instrumented_v, void *>::type
  alloc(size_t size, PSI_memory_key key) {
    return Impl::alloc(size, key);
  }
  template <typename T = Impl>
  static inline typename std::enable_if<!T::is_pfs_instrumented_v, void *>::type
  alloc(size_t size, PSI_memory_key /*key*/) {
    return Impl::alloc(size);
  }
  static inline void free(void *ptr) { Impl::free(ptr); }
  static inline size_t datalen(void *ptr) { return Impl::datalen(ptr); }
};

}  // namespace detail
}  // namespace ut

#endif
