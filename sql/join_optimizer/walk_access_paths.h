/* Copyright (c) 2020, 2021, Oracle and/or its affiliates.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License, version 2.0,
   as published by the Free Software Foundation.

   This program is also distributed with certain software (including
   but not limited to OpenSSL) that is licensed under separate terms,
   as designated in a particular file or component or in included license
   documentation.  The authors of MySQL hereby grant you an additional
   permission to link the program and your derivative works with the
   separately licensed software that they have included with MySQL.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License, version 2.0, for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

#ifndef SQL_JOIN_OPTIMIZER_WALK_ACCESS_PATHS_H
#define SQL_JOIN_OPTIMIZER_WALK_ACCESS_PATHS_H

#include "sql/join_optimizer/access_path.h"

enum class WalkAccessPathPolicy {
  // Stop on _any_ MATERIALIZE or STREAM path, even if they do not cross query
  // blocks.
  // Also stops on APPEND paths, which always cross query blocks.
  STOP_AT_MATERIALIZATION,

  // Stop on MATERIALIZE, STREAM or APPEND paths that cross query blocks.
  ENTIRE_QUERY_BLOCK,

  // Do not stop at any kind of access path, unless func() returns true.
  ENTIRE_TREE
};

/**
  Traverse every access path below `path` (limited to the current query block
  if cross_query_blocks is false), calling func() for each one with pre-
  or post-order traversal. If func() returns true, traversal is stopped early.

  The `join` parameter signifies what query block `path` is part of, since that
  is not implicit from the path itself. The function will track this as it
  changes throughout the tree (in MATERIALIZE or STREAM access paths), and
  will give the correct value to the func() callback. It is only used by
  WalkAccesspath() itself if the policy is ENTIRE_QUERY_BLOCK; if not, it is
  only used for the func() callback, and you can set it to nullptr if you wish.
  func() must have signature func(AccessPath *, const JOIN *).

  Nothing currently uses post-order traversal, but it has been requested for
  future use.
 */
template <class Func>
void WalkAccessPaths(AccessPath *path, const JOIN *join,
                     WalkAccessPathPolicy cross_query_blocks, Func &&func,
                     bool post_order_traversal = false) {
  if (cross_query_blocks == WalkAccessPathPolicy::ENTIRE_QUERY_BLOCK) {
    assert(join != nullptr);
  }
  if (!post_order_traversal) {
    if (func(path, join)) {
      // Stop recursing in this branch.
      return;
    }
  }
  switch (path->type) {
    case AccessPath::TABLE_SCAN:
    case AccessPath::INDEX_SCAN:
    case AccessPath::REF:
    case AccessPath::REF_OR_NULL:
    case AccessPath::EQ_REF:
    case AccessPath::PUSHED_JOIN_REF:
    case AccessPath::FULL_TEXT_SEARCH:
    case AccessPath::CONST_TABLE:
    case AccessPath::MRR:
    case AccessPath::FOLLOW_TAIL:
    case AccessPath::INDEX_RANGE_SCAN:
    case AccessPath::DYNAMIC_INDEX_RANGE_SCAN:
    case AccessPath::TABLE_VALUE_CONSTRUCTOR:
    case AccessPath::FAKE_SINGLE_ROW:
    case AccessPath::ZERO_ROWS:
    case AccessPath::ZERO_ROWS_AGGREGATED:
    case AccessPath::MATERIALIZED_TABLE_FUNCTION:
    case AccessPath::UNQUALIFIED_COUNT:
      // No children.
      return;
    case AccessPath::NESTED_LOOP_JOIN:
      WalkAccessPaths(path->nested_loop_join().outer, join, cross_query_blocks,
                      std::forward<Func &&>(func), post_order_traversal);
      WalkAccessPaths(path->nested_loop_join().inner, join, cross_query_blocks,
                      std::forward<Func &&>(func), post_order_traversal);
      break;
    case AccessPath::NESTED_LOOP_SEMIJOIN_WITH_DUPLICATE_REMOVAL:
      WalkAccessPaths(path->nested_loop_semijoin_with_duplicate_removal().outer,
                      join, cross_query_blocks, std::forward<Func &&>(func),
                      post_order_traversal);
      WalkAccessPaths(path->nested_loop_semijoin_with_duplicate_removal().inner,
                      join, cross_query_blocks, std::forward<Func &&>(func),
                      post_order_traversal);
      break;
    case AccessPath::BKA_JOIN:
      WalkAccessPaths(path->bka_join().outer, join, cross_query_blocks,
                      std::forward<Func &&>(func), post_order_traversal);
      WalkAccessPaths(path->bka_join().inner, join, cross_query_blocks,
                      std::forward<Func &&>(func), post_order_traversal);
      break;
    case AccessPath::HASH_JOIN:
      WalkAccessPaths(path->hash_join().outer, join, cross_query_blocks,
                      std::forward<Func &&>(func), post_order_traversal);
      WalkAccessPaths(path->hash_join().inner, join, cross_query_blocks,
                      std::forward<Func &&>(func), post_order_traversal);
      break;
    case AccessPath::FILTER:
      WalkAccessPaths(path->filter().child, join, cross_query_blocks,
                      std::forward<Func &&>(func), post_order_traversal);
      break;
    case AccessPath::SORT:
      WalkAccessPaths(path->sort().child, join, cross_query_blocks,
                      std::forward<Func &&>(func), post_order_traversal);
      break;
    case AccessPath::AGGREGATE:
      WalkAccessPaths(path->aggregate().child, join, cross_query_blocks,
                      std::forward<Func &&>(func), post_order_traversal);
      break;
    case AccessPath::TEMPTABLE_AGGREGATE:
      WalkAccessPaths(path->temptable_aggregate().subquery_path, join,
                      cross_query_blocks, std::forward<Func &&>(func),
                      post_order_traversal);
      WalkAccessPaths(path->temptable_aggregate().table_path, join,
                      cross_query_blocks, std::forward<Func &&>(func),
                      post_order_traversal);
      break;
    case AccessPath::LIMIT_OFFSET:
      WalkAccessPaths(path->limit_offset().child, join, cross_query_blocks,
                      std::forward<Func &&>(func), post_order_traversal);
      break;
    case AccessPath::STREAM:
      if (cross_query_blocks == WalkAccessPathPolicy::ENTIRE_TREE ||
          (cross_query_blocks == WalkAccessPathPolicy::ENTIRE_QUERY_BLOCK &&
           path->stream().join == join)) {
        WalkAccessPaths(path->stream().child, path->stream().join,
                        cross_query_blocks, std::forward<Func &&>(func),
                        post_order_traversal);
      }
      break;
    case AccessPath::MATERIALIZE:
      WalkAccessPaths(path->materialize().table_path, join, cross_query_blocks,
                      std::forward<Func &&>(func), post_order_traversal);
      for (const MaterializePathParameters::QueryBlock &query_block :
           path->materialize().param->query_blocks) {
        if (cross_query_blocks == WalkAccessPathPolicy::ENTIRE_TREE ||
            (cross_query_blocks == WalkAccessPathPolicy::ENTIRE_QUERY_BLOCK &&
             query_block.join == join)) {
          WalkAccessPaths(query_block.subquery_path, query_block.join,
                          cross_query_blocks, std::forward<Func &&>(func),
                          post_order_traversal);
        }
      }
      break;
    case AccessPath::MATERIALIZE_INFORMATION_SCHEMA_TABLE:
      WalkAccessPaths(path->materialize_information_schema_table().table_path,
                      join, cross_query_blocks, std::forward<Func &&>(func),
                      post_order_traversal);
      break;
    case AccessPath::APPEND:
      if (cross_query_blocks != WalkAccessPathPolicy::ENTIRE_TREE) {
        for (const AppendPathParameters &child : *path->append().children) {
          WalkAccessPaths(child.path, child.join, cross_query_blocks,
                          std::forward<Func &&>(func), post_order_traversal);
        }
      }
      break;
    case AccessPath::WINDOW:
      WalkAccessPaths(path->window().child, join, cross_query_blocks,
                      std::forward<Func &&>(func), post_order_traversal);
      break;
    case AccessPath::WEEDOUT:
      WalkAccessPaths(path->weedout().child, join, cross_query_blocks,
                      std::forward<Func &&>(func), post_order_traversal);
      break;
    case AccessPath::REMOVE_DUPLICATES:
      WalkAccessPaths(path->remove_duplicates().child, join, cross_query_blocks,
                      std::forward<Func &&>(func), post_order_traversal);
      break;
    case AccessPath::REMOVE_DUPLICATES_ON_INDEX:
      WalkAccessPaths(path->remove_duplicates_on_index().child, join,
                      cross_query_blocks, std::forward<Func &&>(func),
                      post_order_traversal);
      break;
    case AccessPath::ALTERNATIVE:
      WalkAccessPaths(path->alternative().child, join, cross_query_blocks,
                      std::forward<Func &&>(func), post_order_traversal);
      break;
    case AccessPath::CACHE_INVALIDATOR:
      WalkAccessPaths(path->cache_invalidator().child, join, cross_query_blocks,
                      std::forward<Func &&>(func), post_order_traversal);
      break;
  }
  if (post_order_traversal) {
    if (func(path, join)) {
      // Stop recursing in this branch.
      return;
    }
  }
}

/**
  A wrapper around WalkAccessPaths() that collects all tables under
  “root_path” and calls the given functor, stopping at materializations.
  This is typically used to know which tables to sort or the like.

  func() must have signature func(TABLE *), and return true upon error.
 */
template <class Func>
void WalkTablesUnderAccessPath(AccessPath *root_path, Func &&func) {
  WalkAccessPaths(
      root_path, /*join=*/nullptr,
      WalkAccessPathPolicy::STOP_AT_MATERIALIZATION,
      [&](AccessPath *path, const JOIN *) {
        switch (path->type) {
          case AccessPath::TABLE_SCAN:
            return func(path->table_scan().table);
          case AccessPath::INDEX_SCAN:
            return func(path->index_scan().table);
          case AccessPath::REF:
            return func(path->ref().table);
          case AccessPath::REF_OR_NULL:
            return func(path->ref_or_null().table);
          case AccessPath::EQ_REF:
            return func(path->eq_ref().table);
          case AccessPath::PUSHED_JOIN_REF:
            return func(path->pushed_join_ref().table);
          case AccessPath::FULL_TEXT_SEARCH:
            return func(path->full_text_search().table);
          case AccessPath::CONST_TABLE:
            return func(path->const_table().table);
          case AccessPath::MRR:
            return func(path->mrr().table);
          case AccessPath::FOLLOW_TAIL:
            return func(path->follow_tail().table);
          case AccessPath::INDEX_RANGE_SCAN:
            return func(path->index_range_scan().table);
          case AccessPath::DYNAMIC_INDEX_RANGE_SCAN:
            return func(path->dynamic_index_range_scan().table);
          case AccessPath::STREAM:
            return func(path->stream().table);
          case AccessPath::MATERIALIZE:
            return func(path->materialize().param->table);
          case AccessPath::MATERIALIZED_TABLE_FUNCTION:
            return func(path->materialized_table_function().table);
          case AccessPath::ALTERNATIVE:
            return func(
                path->alternative().table_scan_path->table_scan().table);
          case AccessPath::UNQUALIFIED_COUNT:
            // Should never be below anything that needs
            // WalkTablesUnderAccessPath().
            assert(false);
            return true;
          case AccessPath::AGGREGATE:
          case AccessPath::APPEND:
          case AccessPath::BKA_JOIN:
          case AccessPath::CACHE_INVALIDATOR:
          case AccessPath::FAKE_SINGLE_ROW:
          case AccessPath::FILTER:
          case AccessPath::HASH_JOIN:
          case AccessPath::LIMIT_OFFSET:
          case AccessPath::MATERIALIZE_INFORMATION_SCHEMA_TABLE:
          case AccessPath::NESTED_LOOP_JOIN:
          case AccessPath::NESTED_LOOP_SEMIJOIN_WITH_DUPLICATE_REMOVAL:
          case AccessPath::REMOVE_DUPLICATES:
          case AccessPath::REMOVE_DUPLICATES_ON_INDEX:
          case AccessPath::SORT:
          case AccessPath::TABLE_VALUE_CONSTRUCTOR:
          case AccessPath::TEMPTABLE_AGGREGATE:
          case AccessPath::WEEDOUT:
          case AccessPath::WINDOW:
          case AccessPath::ZERO_ROWS:
          case AccessPath::ZERO_ROWS_AGGREGATED:
            return false;
        }
        assert(false);
      });
}

#endif  // SQL_JOIN_OPTIMIZER_WALK_ACCESS_PATHS_H
