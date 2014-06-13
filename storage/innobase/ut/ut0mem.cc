/*****************************************************************************

Copyright (c) 1994, 2014, Oracle and/or its affiliates. All Rights Reserved.

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

/********************************************************************//**
@file ut/ut0mem.cc
Memory primitives

Created 5/11/1994 Heikki Tuuri
*************************************************************************/

#include "ut0mem.h"

#ifdef UNIV_NONINL
#include "ut0mem.ic"
#endif

#ifndef UNIV_HOTBACKUP
# include "os0thread.h"
# include "srv0srv.h"
# include <stdlib.h>
#endif /* !UNIV_HOTBACKUP */

const char*	OUT_OF_MEMORY_MSG =
	"Check if you should increase the swap file or ulimits of your"
	" operating system.  On FreeBSD check that you have compiled the OS"
	" with a big enough maximum process size.  Note that on most 32-bit"
	" computers the process memory space is limited to 2 GB or 4 GB.";

/** The number of attempts to make when trying to allcate memory, pausing
for 1 second between attempts to allow some memory to be freed. */
static const int	max_attempts = 60;

/** Allocate memory.
@param[in]	size	number of bytes to allocate
@return allocated memory block */

void*
ut_malloc(
	ulint	size)
{
	void*	ptr = malloc(size);

	for (int retry = 1; ; retry++) {
		if (ptr != NULL) {
			return(ptr);
		}
		if (retry > max_attempts) {
			break;
		}

		/* Sleep for a second and retry the allocation;
		maybe this is just a temporary shortage of memory */

		os_thread_sleep(1000000);

		ptr = malloc(size);
	}

	ib_logf(IB_LOG_LEVEL_FATAL,
		"Cannot allocate " ULINTPF " bytes of memory after %d"
		" tries over %d seconds. OS error: %d-%s. %s",
		size, max_attempts, max_attempts,
		errno, strerror(errno), OUT_OF_MEMORY_MSG);

	return(NULL);
}

/** Allocate zero-filled memory.
@param[in]	n number of bytes to allocate
@return zero-filled allocated memory block */

void*
ut_zalloc(
	ulint	size)
{
	void*	ptr = calloc(size, 1);

	for (int retry = 1; ; retry++) {
		if (ptr != NULL) {
			return(ptr);
		}
		if (retry > max_attempts) {
			break;
		}

		/* Sleep for a second and retry the allocation;
		maybe this is just a temporary shortage of memory */

		os_thread_sleep(1000000);

		ptr = calloc(size, 1);
	}

	ib_logf(IB_LOG_LEVEL_FATAL,
		"Cannot allocate " ULINTPF " bytes of memory after %d"
		" tries over %d seconds. OS error: %d-%s. %s",
		size, max_attempts, max_attempts,
		errno, strerror(errno), OUT_OF_MEMORY_MSG);

	return(NULL);
}

/**********************************************************************//**
Frees a memory block allocated with ut_malloc.
Freeing a NULL pointer is a no-op.
@param[in,out]	mem	memory block, can be NULL */

void
ut_free(
	void* ptr)
{
	free(ptr);
}

#ifndef UNIV_HOTBACKUP
/** Wrapper for realloc().
@param[in,out]	ptr	pointer to old memory block or NULL
@param[in]	size	desired size
@return own: pointer to new memory block or NULL */

void*
ut_realloc(
	void*	ptr,
	ulint	size)
{
	if (size == 0) {
		free(ptr);
		return(NULL);
	}

	void*	new_ptr = realloc(ptr, size);

	for (int retry = 1; ; retry++) {
		if (new_ptr != NULL) {
			return(new_ptr);
		}
		if (retry > max_attempts) {
			break;
		}

		/* Sleep for a second and retry the re-allocation;
		maybe this is just a temporary shortage of memory */

		os_thread_sleep(1000000);

		new_ptr = realloc(ptr, size);
	}

	ib_logf(IB_LOG_LEVEL_FATAL,
		"Cannot re-allocate " ULINTPF " bytes of memory after %d"
		" tries over %d seconds. OS error: %d-%s. %s",
		size, max_attempts, max_attempts,
		errno, strerror(errno), OUT_OF_MEMORY_MSG);

	return(NULL);
}
#endif /* !UNIV_HOTBACKUP */

/**********************************************************************//**
Copies up to size - 1 characters from the NUL-terminated string src to
dst, NUL-terminating the result. Returns strlen(src), so truncation
occurred if the return value >= size.
@return strlen(src) */

ulint
ut_strlcpy(
/*=======*/
	char*		dst,	/*!< in: destination buffer */
	const char*	src,	/*!< in: source buffer */
	ulint		size)	/*!< in: size of destination buffer */
{
	ulint	src_size = strlen(src);

	if (size != 0) {
		ulint	n = ut_min(src_size, size - 1);

		memcpy(dst, src, n);
		dst[n] = '\0';
	}

	return(src_size);
}

/**********************************************************************//**
Like ut_strlcpy, but if src doesn't fit in dst completely, copies the last
(size - 1) bytes of src, not the first.
@return strlen(src) */

ulint
ut_strlcpy_rev(
/*===========*/
	char*		dst,	/*!< in: destination buffer */
	const char*	src,	/*!< in: source buffer */
	ulint		size)	/*!< in: size of destination buffer */
{
	ulint	src_size = strlen(src);

	if (size != 0) {
		ulint	n = ut_min(src_size, size - 1);

		memcpy(dst, src + src_size - n, n + 1);
	}

	return(src_size);
}

#ifndef UNIV_HOTBACKUP
/**********************************************************************//**
Return the number of times s2 occurs in s1. Overlapping instances of s2
are only counted once.
@return the number of times s2 occurs in s1 */

ulint
ut_strcount(
/*========*/
	const char*	s1,	/*!< in: string to search in */
	const char*	s2)	/*!< in: string to search for */
{
	ulint	count = 0;
	ulint	len = strlen(s2);

	if (len == 0) {

		return(0);
	}

	for (;;) {
		s1 = strstr(s1, s2);

		if (!s1) {

			break;
		}

		count++;
		s1 += len;
	}

	return(count);
}

/********************************************************************
Concatenate 3 strings.*/

char*
ut_str3cat(
/*=======*/
				/* out, own: concatenated string, must be
				freed with ut_free() */
	const char*	s1,	/* in: string 1 */
	const char*	s2,	/* in: string 2 */
	const char*	s3)	/* in: string 3 */
{
	char*	s;
	ulint	s1_len = strlen(s1);
	ulint	s2_len = strlen(s2);
	ulint	s3_len = strlen(s3);

	s = static_cast<char*>(ut_malloc(s1_len + s2_len + s3_len + 1));

	memcpy(s, s1, s1_len);
	memcpy(s + s1_len, s2, s2_len);
	memcpy(s + s1_len + s2_len, s3, s3_len);

	s[s1_len + s2_len + s3_len] = '\0';

	return(s);
}
/**********************************************************************//**
Replace every occurrence of s1 in str with s2. Overlapping instances of s1
are only replaced once.
@return own: modified string, must be freed with ut_free() */

char*
ut_strreplace(
/*==========*/
	const char*	str,	/*!< in: string to operate on */
	const char*	s1,	/*!< in: string to replace */
	const char*	s2)	/*!< in: string to replace s1 with */
{
	char*		new_str;
	char*		ptr;
	const char*	str_end;
	ulint		str_len = strlen(str);
	ulint		s1_len = strlen(s1);
	ulint		s2_len = strlen(s2);
	ulint		count = 0;
	int		len_delta = (int) s2_len - (int) s1_len;

	str_end = str + str_len;

	if (len_delta <= 0) {
		len_delta = 0;
	} else {
		count = ut_strcount(str, s1);
	}

	new_str = static_cast<char*>(
		ut_malloc(str_len + count * len_delta + 1));

	ptr = new_str;

	while (str) {
		const char*	next = strstr(str, s1);

		if (!next) {
			next = str_end;
		}

		memcpy(ptr, str, next - str);
		ptr += next - str;

		if (next == str_end) {

			break;
		}

		memcpy(ptr, s2, s2_len);
		ptr += s2_len;

		str = next + s1_len;
	}

	*ptr = '\0';

	return(new_str);
}

#endif /* !UNIV_HOTBACKUP */
