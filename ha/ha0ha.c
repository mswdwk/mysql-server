/************************************************************************
The hash table with external chains

(c) 1994-1997 Innobase Oy

Created 8/22/1994 Heikki Tuuri
*************************************************************************/

#include "ha0ha.h"
#ifdef UNIV_NONINL
#include "ha0ha.ic"
#endif

#ifdef UNIV_DEBUG
# include "buf0buf.h"
#endif /* UNIV_DEBUG */
#include "page0page.h"

/*****************************************************************
Creates a hash table with >= n array cells. The actual number of cells is
chosen to be a prime number slightly bigger than n. */

hash_table_t*
ha_create(
/*======*/
				/* out, own: created table */
	ulint	n,		/* in: number of array cells */
	ulint	n_mutexes,	/* in: number of mutexes to protect the
				hash table: must be a power of 2, or 0 */
	ulint	mutex_level)	/* in: level of the mutexes in the latching
				order: this is used in the debug version */
{
	hash_table_t*	table;
	ulint		i;

	table = hash_create(n);

#ifdef UNIV_DEBUG
	table->adaptive = TRUE;
#endif /* UNIV_DEBUG */
	/* Creating MEM_HEAP_BTR_SEARCH type heaps can potentially fail,
	but in practise it never should in this case, hence the asserts. */

	if (n_mutexes == 0) {
		table->heap = mem_heap_create_in_btr_search(4096);
		ut_a(table->heap);

		return(table);
	}

	hash_create_mutexes(table, n_mutexes, mutex_level);

	table->heaps = mem_alloc(n_mutexes * sizeof(void*));

	for (i = 0; i < n_mutexes; i++) {
		table->heaps[i] = mem_heap_create_in_btr_search(4096);
		ut_a(table->heaps[i]);
	}

	return(table);
}

/*****************************************************************
Inserts an entry into a hash table. If an entry with the same fold number
is found, its node is updated to point to the new data, and no new node
is inserted. */

ibool
ha_insert_for_fold(
/*===============*/
				/* out: TRUE if succeed, FALSE if no more
				memory could be allocated */
	hash_table_t*	table,	/* in: hash table */
	ulint		fold,	/* in: folded value of data; if a node with
				the same fold value already exists, it is
				updated to point to the same data, and no new
				node is created! */
	void*		data)	/* in: data, must not be NULL */
{
	hash_cell_t*	cell;
	ha_node_t*	node;
	ha_node_t*	prev_node;
#ifdef UNIV_DEBUG
	buf_block_t*	prev_block;
#endif /* UNIV_DEBUG */
	ulint		hash;

	ut_ad(table && data);
#ifdef UNIV_SYNC_DEBUG
	ut_ad(!table->mutexes || mutex_own(hash_get_mutex(table, fold)));
#endif /* UNIV_SYNC_DEBUG */
	hash = hash_calc_hash(fold, table);

	cell = hash_get_nth_cell(table, hash);

	prev_node = cell->node;

	while (prev_node != NULL) {
		if (prev_node->fold == fold) {
#ifdef UNIV_DEBUG
			if (table->adaptive) {
				mutex_enter(&buf_pool->mutex);
				prev_block = buf_block_align(prev_node->data);
				ut_a(prev_block->n_pointers > 0);
				prev_block->n_pointers--;
				buf_block_align(data)->n_pointers++;
				mutex_exit(&buf_pool->mutex);
			}
#endif /* UNIV_DEBUG */
			prev_node->data = data;

			return(TRUE);
		}

		prev_node = prev_node->next;
	}

	/* We have to allocate a new chain node */

	node = mem_heap_alloc(hash_get_heap(table, fold), sizeof(ha_node_t));

	if (node == NULL) {
		/* It was a btr search type memory heap and at the moment
		no more memory could be allocated: return */

		ut_ad(hash_get_heap(table, fold)->type & MEM_HEAP_BTR_SEARCH);

		return(FALSE);
	}

	ha_node_set_data(node, data);

#ifdef UNIV_DEBUG
	if (table->adaptive) {
		mutex_enter(&buf_pool->mutex);
		buf_block_align(data)->n_pointers++;
		mutex_exit(&buf_pool->mutex);
	}
#endif /* UNIV_DEBUG */
	node->fold = fold;

	node->next = NULL;

	prev_node = cell->node;

	if (prev_node == NULL) {

		cell->node = node;

		return(TRUE);
	}

	while (prev_node->next != NULL) {

		prev_node = prev_node->next;
	}

	prev_node->next = node;

	return(TRUE);
}

/***************************************************************
Deletes a hash node. */

void
ha_delete_hash_node(
/*================*/
	hash_table_t*	table,		/* in: hash table */
	buf_block_t*	block __attribute__((unused)),
					/* in: buffer block, or NULL */
	ha_node_t*	del_node)	/* in: node to be deleted */
{
#ifdef UNIV_DEBUG
	if (table->adaptive) {
		ut_a(block->frame = page_align(del_node->data));
		ut_a(block->n_pointers > 0);
		block->n_pointers--;
	}
#endif /* UNIV_DEBUG */
	HASH_DELETE_AND_COMPACT(ha_node_t, next, table, del_node);
}

/*****************************************************************
Deletes an entry from a hash table. */

void
ha_delete(
/*======*/
	hash_table_t*	table,	/* in: hash table */
	ulint		fold,	/* in: folded value of data */
	buf_block_t*	block __attribute__((unused)),
					/* in: buffer block, or NULL */
	void*		data)	/* in: data, must not be NULL and must exist
				in the hash table */
{
	ha_node_t*	node;

#ifdef UNIV_SYNC_DEBUG
	ut_ad(!table->mutexes || mutex_own(hash_get_mutex(table, fold)));
#endif /* UNIV_SYNC_DEBUG */
	node = ha_search_with_data(table, fold, data);

	ut_a(node);

	ha_delete_hash_node(table, block, node);
}

/*************************************************************
Looks for an element when we know the pointer to the data, and updates
the pointer to data, if found. */

void
ha_search_and_update_if_found(
/*==========================*/
	hash_table_t*	table,	/* in: hash table */
	ulint		fold,	/* in: folded value of the searched data */
	void*		data,	/* in: pointer to the data */
	void*		new_data)/* in: new pointer to the data */
{
	ha_node_t*	node;

#ifdef UNIV_SYNC_DEBUG
	ut_ad(!table->mutexes || mutex_own(hash_get_mutex(table, fold)));
#endif /* UNIV_SYNC_DEBUG */

	node = ha_search_with_data(table, fold, data);

	if (node) {
#ifdef UNIV_DEBUG
		if (table->adaptive) {
			mutex_enter(&buf_pool->mutex);
			ut_a(buf_block_align(node->data)->n_pointers > 0);
			buf_block_align(node->data)->n_pointers--;
			buf_block_align(new_data)->n_pointers++;
			mutex_exit(&buf_pool->mutex);
		}
#endif /* UNIV_DEBUG */
		node->data = new_data;
	}
}

/*********************************************************************
Removes from the chain determined by fold all nodes whose data pointer
points to the page given. */

void
ha_remove_all_nodes_to_page(
/*========================*/
	hash_table_t*	table,	/* in: hash table */
	ulint		fold,	/* in: fold value */
	buf_block_t*	block,	/* in: buffer block */
	const page_t*	page)	/* in: buffer page */
{
	ha_node_t*	node;

	ut_ad(block->frame == page);
#ifdef UNIV_SYNC_DEBUG
	ut_ad(!table->mutexes || mutex_own(hash_get_mutex(table, fold)));
#endif /* UNIV_SYNC_DEBUG */
	node = ha_chain_get_first(table, fold);

	while (node) {
		if (page_align(ha_node_get_data(node)) == page) {

			/* Remove the hash node */

			ha_delete_hash_node(table, block, node);

			/* Start again from the first node in the chain
			because the deletion may compact the heap of
			nodes and move other nodes! */

			node = ha_chain_get_first(table, fold);
		} else {
			node = ha_chain_get_next(node);
		}
	}
#ifdef UNIV_DEBUG
	/* Check that all nodes really got deleted */

	node = ha_chain_get_first(table, fold);

	while (node) {
		ut_a(page_align(ha_node_get_data(node)) != page);

		node = ha_chain_get_next(node);
	}
#endif
}

/*****************************************************************
Validates a given range of the cells in hash table. */

ibool
ha_validate(
/*========*/
					/* out: TRUE if ok */
	hash_table_t*	table,		/* in: hash table */
	ulint		start_index,	/* in: start index */
	ulint		end_index)	/* in: end index */
{
	hash_cell_t*	cell;
	ha_node_t*	node;
	ibool		ok	= TRUE;
	ulint		i;

	ut_a(start_index <= end_index);
	ut_a(start_index < hash_get_n_cells(table));
	ut_a(end_index < hash_get_n_cells(table));

	for (i = start_index; i <= end_index; i++) {

		cell = hash_get_nth_cell(table, i);

		node = cell->node;

		while (node) {
			if (hash_calc_hash(node->fold, table) != i) {
				ut_print_timestamp(stderr);
				fprintf(stderr,
					"InnoDB: Error: hash table node"
					" fold value %lu does not\n"
					"InnoDB: match the cell number %lu.\n",
					(ulong) node->fold, (ulong) i);

				ok = FALSE;
			}

			node = node->next;
		}
	}

	return(ok);
}

/*****************************************************************
Prints info of a hash table. */

void
ha_print_info(
/*==========*/
	FILE*		file,	/* in: file where to print */
	hash_table_t*	table)	/* in: hash table */
{
	hash_cell_t*	cell;
	ulint		cells	= 0;
	ulint		n_bufs;
	ulint		i;

	for (i = 0; i < hash_get_n_cells(table); i++) {

		cell = hash_get_nth_cell(table, i);

		if (cell->node) {

			cells++;
		}
	}

	fprintf(file,
		"Hash table size %lu, used cells %lu",
		(ulong) hash_get_n_cells(table), (ulong) cells);

	if (table->heaps == NULL && table->heap != NULL) {

		/* This calculation is intended for the adaptive hash
		index: how many buffer frames we have reserved? */

		n_bufs = UT_LIST_GET_LEN(table->heap->base) - 1;

		if (table->heap->free_block) {
			n_bufs++;
		}

		fprintf(file, ", node heap has %lu buffer(s)\n",
			(ulong) n_bufs);
	}
}
