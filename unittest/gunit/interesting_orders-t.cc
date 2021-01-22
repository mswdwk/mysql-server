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

#include <gtest/gtest.h>

#include <array>

#include "sql/item.h"
#include "sql/join_optimizer/interesting_orders.h"
#include "unittest/gunit/fake_table.h"
#include "unittest/gunit/test_utils.h"

using std::array;
using std::unique_ptr;

TEST(InterestingOrderingTest, DeduplicateHandles) {
  my_testing::Server_initializer m_initializer;
  m_initializer.SetUp();
  LogicalOrderings orderings(m_initializer.thd());

  EXPECT_EQ(1, orderings.GetHandle(new Item_int(1)));
  EXPECT_EQ(2, orderings.GetHandle(new Item_int(2)));
  EXPECT_EQ(1, orderings.GetHandle(new Item_int(1)));
  EXPECT_EQ(3, orderings.GetHandle(new Item_int(10)));
}

TEST(InterestingOrderingTest, DeduplicateOrderings) {
  my_testing::Server_initializer m_initializer;
  m_initializer.SetUp();
  THD *thd = m_initializer.thd();

  LogicalOrderings orderings(thd);
  ItemHandle i1 = orderings.GetHandle(new Item_int(1));
  ItemHandle i2 = orderings.GetHandle(new Item_int(2));
  ItemHandle i3 = orderings.GetHandle(new Item_int(3));

  array<OrderElement, 2> order_a{OrderElement{i1, ORDER_ASC},
                                 OrderElement{i2, ORDER_ASC}};
  EXPECT_EQ(
      1, orderings.AddOrdering(thd, Ordering{order_a}, /*interesting=*/false));
  EXPECT_FALSE(orderings.ordering_is_relevant_for_sortahead(1));

  array<OrderElement, 2> order_b{OrderElement{i1, ORDER_ASC},
                                 OrderElement{i3, ORDER_ASC}};
  EXPECT_EQ(
      2, orderings.AddOrdering(thd, Ordering{order_b}, /*interesting=*/true));
  EXPECT_TRUE(orderings.ordering_is_relevant_for_sortahead(2));
  EXPECT_EQ(
      1, orderings.AddOrdering(thd, Ordering{order_a}, /*interesting=*/true));
  EXPECT_TRUE(orderings.ordering_is_relevant_for_sortahead(1));

  array<OrderElement, 2> order_equiv_a{OrderElement{i1, ORDER_ASC},
                                       OrderElement{i2, ORDER_ASC}};
  EXPECT_EQ(1, orderings.AddOrdering(thd, Ordering{order_equiv_a},
                                     /*interesting=*/true));

  array<OrderElement, 2> grouping_a{OrderElement{i1, ORDER_NOT_RELEVANT},
                                    OrderElement{i2, ORDER_NOT_RELEVANT}};
  EXPECT_EQ(3, orderings.AddOrdering(thd, Ordering{grouping_a},
                                     /*interesting=*/true));
}

TEST(InterestingOrderingTest, DeduplicateFunctionalDependencies) {
  my_testing::Server_initializer m_initializer;
  m_initializer.SetUp();
  THD *thd = m_initializer.thd();

  LogicalOrderings orderings(thd);
  ItemHandle i1 = orderings.GetHandle(new Item_int(1));
  ItemHandle i2 = orderings.GetHandle(new Item_int(2));

  // Add i1 = i2.
  array<ItemHandle, 1> head_i1{i1};
  FunctionalDependency fd_equiv;
  fd_equiv.type = FunctionalDependency::EQUIVALENCE;
  fd_equiv.head = Bounds_checked_array<ItemHandle>(head_i1);
  fd_equiv.tail = i2;
  EXPECT_EQ(1, orderings.AddFunctionalDependency(thd, fd_equiv));

  // Invert the equivalence; it should still be deduplicated away.
  array<ItemHandle, 1> head_i2{i2};
  fd_equiv.head = Bounds_checked_array<ItemHandle>(head_i2);
  fd_equiv.tail = i1;
  EXPECT_EQ(1, orderings.AddFunctionalDependency(thd, fd_equiv));

  // Add i1 → i2.
  FunctionalDependency fd_12;
  fd_12.type = FunctionalDependency::FD;
  fd_12.head = Bounds_checked_array<ItemHandle>(head_i1);
  fd_12.tail = i2;
  EXPECT_EQ(2, orderings.AddFunctionalDependency(thd, fd_12));
  EXPECT_EQ(2, orderings.AddFunctionalDependency(thd, fd_12));

  EXPECT_EQ(1, orderings.AddFunctionalDependency(thd, fd_equiv));

  // Add i2 → i1. It is different from i1 → i2.
  fd_12.head = Bounds_checked_array<ItemHandle>(head_i2);
  fd_12.tail = i1;
  EXPECT_EQ(3, orderings.AddFunctionalDependency(thd, fd_12));
}

TEST(InterestingOrderingTest, PruneFunctionalDependencies) {
  my_testing::Server_initializer m_initializer;
  m_initializer.SetUp();
  THD *thd = m_initializer.thd();

  LogicalOrderings orderings(thd);
  ItemHandle i1 = orderings.GetHandle(new Item_int(1));
  ItemHandle i2 = orderings.GetHandle(new Item_int(2));
  ItemHandle i3 = orderings.GetHandle(new Item_int(3));
  ItemHandle i4 = orderings.GetHandle(new Item_int(4));

  // i1 and i2 are part of an interesting order.
  array<OrderElement, 2> order_a{OrderElement{i1, ORDER_ASC},
                                 OrderElement{i2, ORDER_ASC}};
  EXPECT_EQ(
      1, orderings.AddOrdering(thd, Ordering{order_a}, /*interesting=*/true));

  // Add i1 -> i3. It should be pruned, since i3 is not part of
  // an interesting order.
  array<ItemHandle, 1> head_i1{i1};
  FunctionalDependency fd_13;
  fd_13.type = FunctionalDependency::FD;
  fd_13.head = Bounds_checked_array<ItemHandle>(head_i1);
  fd_13.tail = i3;
  int fd_13_idx = orderings.AddFunctionalDependency(thd, fd_13);

  // Add {} -> i1. It should be kept, since i1 is part of an interesting order.
  FunctionalDependency fd_create_1;
  fd_create_1.type = FunctionalDependency::FD;
  fd_create_1.head = Bounds_checked_array<ItemHandle>();
  fd_create_1.tail = i1;
  int fd_create_1_idx = orderings.AddFunctionalDependency(thd, fd_create_1);

  // Add {} → i4 and i2 = i4. These should both be kept, since i2 is part of
  // and interesting order (and i2 = i4 counts as i4 → i2).
  FunctionalDependency fd_create_4;
  fd_create_4.type = FunctionalDependency::FD;
  fd_create_4.head = Bounds_checked_array<ItemHandle>();
  fd_create_4.tail = i4;
  int fd_create_4_idx = orderings.AddFunctionalDependency(thd, fd_create_4);

  array<ItemHandle, 1> head_i2{i2};
  FunctionalDependency fd_24;
  fd_24.type = FunctionalDependency::EQUIVALENCE;
  fd_24.head = Bounds_checked_array<ItemHandle>(head_i2);
  fd_24.tail = i4;
  int fd_24_idx = orderings.AddFunctionalDependency(thd, fd_24);

  string trace;
  orderings.Build(thd, &trace);
  SCOPED_TRACE(trace);  // Prints out the trace on failure.

  EXPECT_TRUE(orderings.GetFDSet(fd_13_idx).none());
  EXPECT_FALSE(orderings.GetFDSet(fd_create_1_idx).none());
  EXPECT_FALSE(orderings.GetFDSet(fd_create_4_idx).none());
  EXPECT_FALSE(orderings.GetFDSet(fd_24_idx).none());
}

class InterestingOrderingTableTest : public ::testing::Test {
 public:
  InterestingOrderingTableTest() {
    m_initializer.SetUp();
    m_orderings.reset(new LogicalOrderings(m_initializer.thd()));

    m_table.reset(new Fake_TABLE(/*num_columns=*/5, /*nullable=*/true));
    m_table->field[0]->field_name = "a";
    m_table->field[1]->field_name = "b";
    m_table->field[2]->field_name = "c";
    m_table->field[3]->field_name = "d";
    m_table->field[4]->field_name = "e";

    a = m_orderings->GetHandle(new Item_field(m_table->field[0]));
    b = m_orderings->GetHandle(new Item_field(m_table->field[1]));
    c = m_orderings->GetHandle(new Item_field(m_table->field[2]));
    d = m_orderings->GetHandle(new Item_field(m_table->field[3]));
    e = m_orderings->GetHandle(new Item_field(m_table->field[4]));
  }

 protected:
  my_testing::Server_initializer m_initializer;
  unique_ptr<LogicalOrderings> m_orderings;
  unique_ptr<Fake_TABLE> m_table;
  ItemHandle a, b, c, d, e;
};

TEST_F(InterestingOrderingTableTest, HomogenizeOrderings) {
  THD *thd = m_initializer.thd();

  // Add two tables, with some columns.
  unique_ptr_destroy_only<Fake_TABLE> t1(
      new (thd->mem_root) Fake_TABLE(/*num_columns=*/3, /*nullable=*/true));
  t1->field[0]->field_name = "a";
  t1->field[1]->field_name = "b";
  t1->field[2]->field_name = "c";
  ItemHandle t1_a = m_orderings->GetHandle(new Item_field(t1->field[0]));
  ItemHandle t1_b = m_orderings->GetHandle(new Item_field(t1->field[1]));
  ItemHandle t1_c = m_orderings->GetHandle(new Item_field(t1->field[2]));

  unique_ptr_destroy_only<Fake_TABLE> t2(
      new (thd->mem_root) Fake_TABLE(/*num_columns=*/3, /*nullable=*/true));
  t2->field[0]->field_name = "a";
  t2->field[1]->field_name = "b";
  t2->field[2]->field_name = "c";
  ItemHandle t2_a = m_orderings->GetHandle(new Item_field(t2->field[0]));
  // t2_b is unused.
  ItemHandle t2_c = m_orderings->GetHandle(new Item_field(t2->field[2]));

  // Add t1.a = t2.a.
  array<ItemHandle, 1> head_t1_a{t1_a};
  FunctionalDependency fd_equiv;
  fd_equiv.type = FunctionalDependency::EQUIVALENCE;
  fd_equiv.head = Bounds_checked_array<ItemHandle>(head_t1_a);
  fd_equiv.tail = t2_a;
  m_orderings->AddFunctionalDependency(thd, fd_equiv);

  // Add t1.a → t1.b.
  FunctionalDependency fd_ab;
  fd_ab.type = FunctionalDependency::FD;
  fd_ab.head = Bounds_checked_array<ItemHandle>(head_t1_a);
  fd_ab.tail = t1_b;
  m_orderings->AddFunctionalDependency(thd, fd_ab);

  // Set up the ordering (t1.a, t2.a). It should be homogenized into (t1.a)
  // and (t2.a) due to the equivalence.
  array<OrderElement, 2> order_aa{OrderElement{t1_a, ORDER_ASC},
                                  OrderElement{t2_a, ORDER_ASC}};
  EXPECT_EQ(1, m_orderings->AddOrdering(thd, Ordering{order_aa},
                                        /*interesting=*/true));

  // Add the ordering (t2.a, t1.b, t1.c↓). It should be homogenized into
  // (t1.a, t1.c↓); the t1.b is optimized away due to the FD.
  array<OrderElement, 3> order_abc{OrderElement{t2_a, ORDER_ASC},
                                   OrderElement{t1_b, ORDER_ASC},
                                   OrderElement{t1_c, ORDER_DESC}};
  EXPECT_EQ(2, m_orderings->AddOrdering(thd, Ordering{order_abc},
                                        /*interesting=*/true));

  // And finally, (t1.a, t1.c, t2.a, t2.c), which cannot be homogenized
  // onto a single table.
  array<OrderElement, 4> order_acac{
      OrderElement{t1_a, ORDER_ASC}, OrderElement{t1_c, ORDER_ASC},
      OrderElement{t2_a, ORDER_ASC}, OrderElement{t2_c, ORDER_ASC}};
  EXPECT_EQ(3, m_orderings->AddOrdering(thd, Ordering{order_acac},
                                        /*interesting=*/true));

  string trace;
  m_orderings->Build(thd, &trace);
  SCOPED_TRACE(trace);  // Prints out the trace on failure.

  ASSERT_EQ(7, m_orderings->num_orderings());

  // (t1.a).
  ASSERT_THAT(m_orderings->ordering(4),
              testing::ElementsAre(OrderElement{t1_a, ORDER_ASC}));

  // (t2.a).
  ASSERT_THAT(m_orderings->ordering(5),
              testing::ElementsAre(OrderElement{t2_a, ORDER_ASC}));

  // (t1.a, t1.c↓).
  ASSERT_THAT(m_orderings->ordering(6),
              testing::ElementsAre(OrderElement{t1_a, ORDER_ASC},
                                   OrderElement{t1_c, ORDER_DESC}));
}

TEST_F(InterestingOrderingTableTest, SetOrder) {
  THD *thd = m_initializer.thd();

  unique_ptr_destroy_only<Fake_TABLE> table(
      new (thd->mem_root) Fake_TABLE(/*num_columns=*/3, /*nullable=*/true));
  table->field[0]->field_name = "a";
  table->field[1]->field_name = "b";
  table->field[2]->field_name = "c";

  ItemHandle a = m_orderings->GetHandle(new Item_field(table->field[0]));
  ItemHandle b = m_orderings->GetHandle(new Item_field(table->field[1]));
  ItemHandle c = m_orderings->GetHandle(new Item_field(table->field[2]));

  // Interesting orders are a, a↓, b and bc.
  array<OrderElement, 1> order_a{OrderElement{a, ORDER_ASC}};
  array<OrderElement, 1> order_a_desc{OrderElement{a, ORDER_DESC}};
  array<OrderElement, 1> order_b{OrderElement{b, ORDER_ASC}};
  array<OrderElement, 2> order_bc{OrderElement{b, ORDER_ASC},
                                  OrderElement{c, ORDER_ASC}};
  int a_idx =
      m_orderings->AddOrdering(thd, Ordering(order_a), /*interesting=*/true);
  int a_desc_idx = m_orderings->AddOrdering(thd, Ordering(order_a_desc),
                                            /*interesting=*/true);
  int b_idx =
      m_orderings->AddOrdering(thd, Ordering(order_b), /*interesting=*/true);
  int bc_idx =
      m_orderings->AddOrdering(thd, Ordering(order_bc), /*interesting=*/true);

  string trace;
  m_orderings->Build(thd, &trace);
  SCOPED_TRACE(trace);  // Prints out the trace on failure.

  LogicalOrderings::StateIndex idx;

  idx = m_orderings->SetOrder(a_idx);
  EXPECT_TRUE(m_orderings->DoesFollowOrder(idx, a_idx));
  EXPECT_FALSE(m_orderings->DoesFollowOrder(idx, a_desc_idx));
  EXPECT_FALSE(m_orderings->DoesFollowOrder(idx, b_idx));
  EXPECT_FALSE(m_orderings->DoesFollowOrder(idx, bc_idx));

  idx = m_orderings->SetOrder(a_desc_idx);
  EXPECT_FALSE(m_orderings->DoesFollowOrder(idx, bc_idx));
  EXPECT_TRUE(m_orderings->DoesFollowOrder(idx, a_desc_idx));
  EXPECT_FALSE(m_orderings->DoesFollowOrder(idx, b_idx));
  EXPECT_FALSE(m_orderings->DoesFollowOrder(idx, a_idx));

  idx = m_orderings->SetOrder(b_idx);
  EXPECT_FALSE(m_orderings->DoesFollowOrder(idx, a_desc_idx));
  EXPECT_FALSE(m_orderings->DoesFollowOrder(idx, a_idx));
  EXPECT_TRUE(m_orderings->DoesFollowOrder(idx, b_idx));
  EXPECT_FALSE(m_orderings->DoesFollowOrder(idx, bc_idx));

  idx = m_orderings->SetOrder(bc_idx);
  EXPECT_FALSE(m_orderings->DoesFollowOrder(idx, a_desc_idx));
  EXPECT_FALSE(m_orderings->DoesFollowOrder(idx, a_idx));
  EXPECT_TRUE(m_orderings->DoesFollowOrder(idx, b_idx));
  EXPECT_TRUE(m_orderings->DoesFollowOrder(idx, bc_idx));
}

TEST_F(InterestingOrderingTableTest, BasicTest) {
  THD *thd = m_initializer.thd();

  // Interesting orders are ab, abc, de, abed.
  array<OrderElement, 2> order_ab{OrderElement{a, ORDER_ASC},
                                  OrderElement{b, ORDER_ASC}};
  array<OrderElement, 3> order_abc{OrderElement{a, ORDER_ASC},
                                   OrderElement{b, ORDER_ASC},
                                   OrderElement{c, ORDER_ASC}};
  array<OrderElement, 2> order_de{OrderElement{d, ORDER_ASC},
                                  OrderElement{e, ORDER_ASC}};
  array<OrderElement, 4> order_abed{
      OrderElement{a, ORDER_ASC}, OrderElement{b, ORDER_ASC},
      OrderElement{e, ORDER_ASC}, OrderElement{d, ORDER_ASC}};
  int ab_idx =
      m_orderings->AddOrdering(thd, Ordering(order_ab), /*interesting=*/true);
  int abc_idx =
      m_orderings->AddOrdering(thd, Ordering(order_abc), /*interesting=*/true);
  int de_idx =
      m_orderings->AddOrdering(thd, Ordering(order_de), /*interesting=*/true);
  int abed_idx =
      m_orderings->AddOrdering(thd, Ordering(order_abed), /*interesting=*/true);

  // Add b=d.
  array<ItemHandle, 1> head_b{b};
  FunctionalDependency fd_equiv;
  fd_equiv.type = FunctionalDependency::EQUIVALENCE;
  fd_equiv.head = Bounds_checked_array<ItemHandle>(head_b);
  fd_equiv.tail = d;
  int fd_equiv_idx = m_orderings->AddFunctionalDependency(thd, fd_equiv);

  // Add {a, b} → e.
  array<ItemHandle, 2> head_ab{a, b};
  FunctionalDependency fd_complex;
  fd_complex.type = FunctionalDependency::FD;
  fd_complex.head = Bounds_checked_array<ItemHandle>(head_ab);
  fd_complex.tail = e;
  int fd_complex_idx = m_orderings->AddFunctionalDependency(thd, fd_complex);

  // Finally, add {} → a and {} → d.
  array<ItemHandle, 0> head_empty{};

  FunctionalDependency fd_empty_a;
  fd_empty_a.type = FunctionalDependency::FD;
  fd_empty_a.head = Bounds_checked_array<ItemHandle>(head_empty);
  fd_empty_a.tail = a;
  int fd_empty_a_idx = m_orderings->AddFunctionalDependency(thd, fd_empty_a);

  FunctionalDependency fd_empty_d;
  fd_empty_d.type = FunctionalDependency::FD;
  fd_empty_d.head = Bounds_checked_array<ItemHandle>(head_empty);
  fd_empty_d.tail = d;
  int fd_empty_d_idx = m_orderings->AddFunctionalDependency(thd, fd_empty_d);

  string trace;
  m_orderings->Build(thd, &trace);
  SCOPED_TRACE(trace);  // Prints out the trace on failure.

  LogicalOrderings::StateIndex idx;
  FunctionalDependencySet fds{0};

  // Start with the empty ordering.
  idx = m_orderings->SetOrder(0);

  // Apply {} → a and {} → d.
  fds |= m_orderings->GetFDSet(fd_empty_a_idx);
  fds |= m_orderings->GetFDSet(fd_empty_d_idx);
  idx = m_orderings->ApplyFDs(idx, fds);

  EXPECT_FALSE(m_orderings->DoesFollowOrder(idx, ab_idx));
  EXPECT_FALSE(m_orderings->DoesFollowOrder(idx, abc_idx));
  EXPECT_FALSE(m_orderings->DoesFollowOrder(idx, de_idx));
  EXPECT_FALSE(m_orderings->DoesFollowOrder(idx, abed_idx));

  // Apply b = d. Now we should follow ab.
  FunctionalDependencySet backup_fds = fds;
  fds |= m_orderings->GetFDSet(fd_equiv_idx);
  LogicalOrderings::StateIndex idx2 = m_orderings->ApplyFDs(idx, fds);
  EXPECT_TRUE(m_orderings->DoesFollowOrder(idx2, ab_idx));
  EXPECT_FALSE(m_orderings->DoesFollowOrder(idx2, abc_idx));
  EXPECT_FALSE(m_orderings->DoesFollowOrder(idx2, de_idx));
  EXPECT_FALSE(m_orderings->DoesFollowOrder(idx2, abed_idx));

  // Go back and instead apply {a, b} → e. It shouldn't matter much;
  // no orders should match.
  fds = backup_fds;
  fds |= m_orderings->GetFDSet(fd_complex_idx);
  idx = m_orderings->ApplyFDs(idx, fds);
  EXPECT_FALSE(m_orderings->DoesFollowOrder(idx, ab_idx));
  EXPECT_FALSE(m_orderings->DoesFollowOrder(idx, abc_idx));
  EXPECT_FALSE(m_orderings->DoesFollowOrder(idx, de_idx));
  EXPECT_FALSE(m_orderings->DoesFollowOrder(idx, abed_idx));

  // Finally, apply b = d again. This should give us ab _and_ abed
  // (since we now have {a, b}, we also follow e).
  fds |= m_orderings->GetFDSet(fd_equiv_idx);
  idx = m_orderings->ApplyFDs(idx, fds);
  EXPECT_TRUE(m_orderings->DoesFollowOrder(idx, ab_idx));
  EXPECT_FALSE(m_orderings->DoesFollowOrder(idx, abc_idx));
  EXPECT_FALSE(m_orderings->DoesFollowOrder(idx, de_idx));
  EXPECT_TRUE(m_orderings->DoesFollowOrder(idx, abed_idx));
}

TEST_F(InterestingOrderingTableTest, AddReverseElement) {
  THD *thd = m_initializer.thd();

  // Interesting orders are a, ab↓.
  array<OrderElement, 1> order_a{OrderElement{a, ORDER_ASC}};
  array<OrderElement, 2> order_ab{OrderElement{a, ORDER_ASC},
                                  OrderElement{b, ORDER_DESC}};
  int a_idx =
      m_orderings->AddOrdering(thd, Ordering(order_a), /*interesting=*/true);
  int ab_idx =
      m_orderings->AddOrdering(thd, Ordering(order_ab), /*interesting=*/true);

  // Add {a} → b.
  array<ItemHandle, 1> head_a{a};
  FunctionalDependency fd_ab;
  fd_ab.type = FunctionalDependency::FD;
  fd_ab.head = Bounds_checked_array<ItemHandle>(head_a);
  fd_ab.tail = b;
  int fd_ab_idx = m_orderings->AddFunctionalDependency(thd, fd_ab);

  string trace;
  m_orderings->Build(thd, &trace);
  SCOPED_TRACE(trace);  // Prints out the trace on failure.

  LogicalOrderings::StateIndex idx;
  FunctionalDependencySet fds{0};

  // Start with a.
  idx = m_orderings->SetOrder(a_idx);

  EXPECT_TRUE(m_orderings->DoesFollowOrder(idx, a_idx));
  EXPECT_FALSE(m_orderings->DoesFollowOrder(idx, ab_idx));

  // Apply {a} → b, which should make us follow ab↓, too.
  fds |= m_orderings->GetFDSet(fd_ab_idx);
  idx = m_orderings->ApplyFDs(idx, fds);

  EXPECT_TRUE(m_orderings->DoesFollowOrder(idx, a_idx));
  EXPECT_TRUE(m_orderings->DoesFollowOrder(idx, ab_idx));
}

TEST_F(InterestingOrderingTableTest, AddReverseElementThroughEquivalences) {
  THD *thd = m_initializer.thd();

  // Interesting orders are a, ac↓.
  array<OrderElement, 1> order_a{OrderElement{a, ORDER_ASC}};
  array<OrderElement, 2> order_ac{OrderElement{a, ORDER_ASC},
                                  OrderElement{c, ORDER_DESC}};
  int a_idx =
      m_orderings->AddOrdering(thd, Ordering(order_a), /*interesting=*/true);
  int ac_idx =
      m_orderings->AddOrdering(thd, Ordering(order_ac), /*interesting=*/true);

  // Add {a} → b.
  array<ItemHandle, 1> head_a{a};
  FunctionalDependency fd_ab;
  fd_ab.type = FunctionalDependency::FD;
  fd_ab.head = Bounds_checked_array<ItemHandle>(head_a);
  fd_ab.tail = b;
  int fd_ab_idx = m_orderings->AddFunctionalDependency(thd, fd_ab);

  // Add b = c.
  array<ItemHandle, 1> head_b{b};
  FunctionalDependency fd_equiv;
  fd_equiv.type = FunctionalDependency::EQUIVALENCE;
  fd_equiv.head = Bounds_checked_array<ItemHandle>(head_b);
  fd_equiv.tail = c;
  int fd_equiv_idx = m_orderings->AddFunctionalDependency(thd, fd_equiv);

  string trace;
  m_orderings->Build(thd, &trace);
  SCOPED_TRACE(trace);  // Prints out the trace on failure.

  LogicalOrderings::StateIndex idx;
  FunctionalDependencySet fds{0};

  // Start with a, then add both FDs. We should get ac↓ by means of adding ab↓
  // and then converting b to c; note that b↓ should be added even though it
  // was never in an ordering.
  idx = m_orderings->SetOrder(a_idx);
  fds |= m_orderings->GetFDSet(fd_ab_idx);
  fds |= m_orderings->GetFDSet(fd_equiv_idx);
  idx = m_orderings->ApplyFDs(idx, fds);

  EXPECT_TRUE(m_orderings->DoesFollowOrder(idx, a_idx));
  EXPECT_TRUE(m_orderings->DoesFollowOrder(idx, ac_idx));
}

// Demonstrates that the prefix test should not prune away non-strict prefixes
// if it wants to avoid following additional edges.
TEST_F(InterestingOrderingTableTest, DoesNotStrictlyPruneOnPrefixes) {
  THD *thd = m_initializer.thd();

  // Interesting orders are abcd, dc.
  array<OrderElement, 4> order_abcd{
      OrderElement{a, ORDER_ASC}, OrderElement{b, ORDER_ASC},
      OrderElement{c, ORDER_ASC}, OrderElement{d, ORDER_ASC}};
  array<OrderElement, 2> order_dc{OrderElement{d, ORDER_ASC},
                                  OrderElement{c, ORDER_ASC}};
  int abcd_idx =
      m_orderings->AddOrdering(thd, Ordering(order_abcd), /*interesting=*/true);
  int dc_idx =
      m_orderings->AddOrdering(thd, Ordering(order_dc), /*interesting=*/true);

  // Add b=d.
  array<ItemHandle, 1> head_b{b};
  FunctionalDependency fd_equiv;
  fd_equiv.type = FunctionalDependency::EQUIVALENCE;
  fd_equiv.head = Bounds_checked_array<ItemHandle>(head_b);
  fd_equiv.tail = d;
  int fd_equiv_idx = m_orderings->AddFunctionalDependency(thd, fd_equiv);

  // Add {} → a.
  array<ItemHandle, 0> head_empty{};

  FunctionalDependency fd_empty_a;
  fd_empty_a.type = FunctionalDependency::FD;
  fd_empty_a.head = Bounds_checked_array<ItemHandle>(head_empty);
  fd_empty_a.tail = a;
  int fd_empty_a_idx = m_orderings->AddFunctionalDependency(thd, fd_empty_a);

  string trace;
  m_orderings->Build(thd, &trace);
  SCOPED_TRACE(trace);  // Prints out the trace on failure.

  LogicalOrderings::StateIndex idx;
  FunctionalDependencySet fds{0};

  // Start at dc, then apply b=d. This generates, among others, the order
  // (bcd). It is not a prefix of the interesting order abcd, but still,
  // we don't want to prune it out.
  idx = m_orderings->SetOrder(dc_idx);

  EXPECT_TRUE(m_orderings->DoesFollowOrder(idx, dc_idx));
  EXPECT_FALSE(m_orderings->DoesFollowOrder(idx, abcd_idx));

  fds |= m_orderings->GetFDSet(fd_equiv_idx);
  idx = m_orderings->ApplyFDs(idx, fds);

  EXPECT_TRUE(m_orderings->DoesFollowOrder(idx, dc_idx));
  EXPECT_FALSE(m_orderings->DoesFollowOrder(idx, abcd_idx));

  // Now apply {} → a. Note that we break the contract here and don't
  // include b=d in the set of functional dependencies; this is to verify that
  // the state machine didn't actually need to follow b=d again, which it would
  // if the order (bcd) was pruned out earlier. (Then, we'd find it through
  // generating (abc) first in this step, which _is_ a prefix, so this is not
  // about correctness, only performance.)
  fds.reset();
  fds |= m_orderings->GetFDSet(fd_empty_a_idx);
  idx = m_orderings->ApplyFDs(idx, fds);

  EXPECT_TRUE(m_orderings->DoesFollowOrder(idx, dc_idx));
  EXPECT_TRUE(m_orderings->DoesFollowOrder(idx, abcd_idx));
}

// Demonstrates that pruning must take equivalences into account.
TEST_F(InterestingOrderingTableTest, TwoEquivalences) {
  THD *thd = m_initializer.thd();

  // Interesting orders are abc, dec.
  array<OrderElement, 3> order_abc{OrderElement{a, ORDER_ASC},
                                   OrderElement{b, ORDER_ASC},
                                   OrderElement{c, ORDER_ASC}};
  array<OrderElement, 3> order_dec{OrderElement{d, ORDER_ASC},
                                   OrderElement{e, ORDER_ASC},
                                   OrderElement{c, ORDER_ASC}};
  int abc_idx =
      m_orderings->AddOrdering(thd, Ordering(order_abc), /*interesting=*/true);
  int dec_idx =
      m_orderings->AddOrdering(thd, Ordering(order_dec), /*interesting=*/true);

  // Add a=d and b=e.
  array<ItemHandle, 1> head_a{a};
  FunctionalDependency fd_ad;
  fd_ad.type = FunctionalDependency::EQUIVALENCE;
  fd_ad.head = Bounds_checked_array<ItemHandle>(head_a);
  fd_ad.tail = d;
  int fd_ad_idx = m_orderings->AddFunctionalDependency(thd, fd_ad);

  array<ItemHandle, 1> head_b{b};
  FunctionalDependency fd_be;
  fd_be.type = FunctionalDependency::EQUIVALENCE;
  fd_be.head = Bounds_checked_array<ItemHandle>(head_b);
  fd_be.tail = e;
  int fd_be_idx = m_orderings->AddFunctionalDependency(thd, fd_be);

  string trace;
  m_orderings->Build(thd, &trace);
  SCOPED_TRACE(trace);  // Prints out the trace on failure.

  LogicalOrderings::StateIndex idx;
  FunctionalDependencySet fds{0};

  // Start at abc, then apply both a=d and b=e. Now we should have dec.
  // Note that if we did not take equivalences into account when pruning,
  // we could prune away the intermediate dbc ordering and never reach dec.
  idx = m_orderings->SetOrder(abc_idx);

  EXPECT_TRUE(m_orderings->DoesFollowOrder(idx, abc_idx));
  EXPECT_FALSE(m_orderings->DoesFollowOrder(idx, dec_idx));

  fds |= m_orderings->GetFDSet(fd_ad_idx);
  fds |= m_orderings->GetFDSet(fd_be_idx);
  idx = m_orderings->ApplyFDs(idx, fds);

  EXPECT_TRUE(m_orderings->DoesFollowOrder(idx, abc_idx));
  EXPECT_TRUE(m_orderings->DoesFollowOrder(idx, dec_idx));
}

TEST_F(InterestingOrderingTableTest, SortByConst) {
  THD *thd = m_initializer.thd();

  // The only interesting order is ab.
  array<OrderElement, 2> order_ab{OrderElement{a, ORDER_ASC},
                                  OrderElement{b, ORDER_ASC}};
  int ab_idx =
      m_orderings->AddOrdering(thd, Ordering(order_ab), /*interesting=*/true);

  // Add b=c.
  array<ItemHandle, 1> head_b{b};
  FunctionalDependency fd_equiv;
  fd_equiv.type = FunctionalDependency::EQUIVALENCE;
  fd_equiv.head = Bounds_checked_array<ItemHandle>(head_b);
  fd_equiv.tail = c;
  int fd_equiv_idx = m_orderings->AddFunctionalDependency(thd, fd_equiv);

  // Finally, add {} → a and {} → c.
  array<ItemHandle, 0> head_empty{};

  FunctionalDependency fd_empty_a;
  fd_empty_a.type = FunctionalDependency::FD;
  fd_empty_a.head = Bounds_checked_array<ItemHandle>(head_empty);
  fd_empty_a.tail = a;
  int fd_empty_a_idx = m_orderings->AddFunctionalDependency(thd, fd_empty_a);

  FunctionalDependency fd_empty_c;
  fd_empty_c.type = FunctionalDependency::FD;
  fd_empty_c.head = Bounds_checked_array<ItemHandle>(head_empty);
  fd_empty_c.tail = c;
  int fd_empty_c_idx = m_orderings->AddFunctionalDependency(thd, fd_empty_c);

  string trace;
  m_orderings->Build(thd, &trace);
  SCOPED_TRACE(trace);  // Prints out the trace on failure.

  // Start with the empty ordering.
  LogicalOrderings::StateIndex idx = m_orderings->SetOrder(0);
  EXPECT_FALSE(m_orderings->DoesFollowOrder(idx, ab_idx));

  // If we do WHERE b=c AND a=<const> AND c=<const>, we should get (ab).
  FunctionalDependencySet fds{0};
  fds |= m_orderings->GetFDSet(fd_equiv_idx);
  fds |= m_orderings->GetFDSet(fd_empty_a_idx);
  fds |= m_orderings->GetFDSet(fd_empty_c_idx);
  idx = m_orderings->ApplyFDs(idx, fds);

  EXPECT_TRUE(m_orderings->DoesFollowOrder(idx, ab_idx));
}

TEST_F(InterestingOrderingTableTest, AlwaysActiveFD) {
  THD *thd = m_initializer.thd();

  // Interesting orderings are ab and b.
  array<OrderElement, 2> order_ab{OrderElement{a, ORDER_ASC},
                                  OrderElement{b, ORDER_ASC}};
  array<OrderElement, 1> order_b{OrderElement{a, ORDER_ASC}};
  int ab_idx =
      m_orderings->AddOrdering(thd, Ordering(order_ab), /*interesting=*/true);
  int b_idx =
      m_orderings->AddOrdering(thd, Ordering(order_b), /*interesting=*/true);

  // Add {} → a and {} → b, but the former is always active.
  array<ItemHandle, 0> head_empty{};

  FunctionalDependency fd_empty_a;
  fd_empty_a.type = FunctionalDependency::FD;
  fd_empty_a.head = Bounds_checked_array<ItemHandle>(head_empty);
  fd_empty_a.tail = a;
  fd_empty_a.always_active = true;
  int fd_empty_a_idx = m_orderings->AddFunctionalDependency(thd, fd_empty_a);

  FunctionalDependency fd_empty_b;
  fd_empty_b.type = FunctionalDependency::FD;
  fd_empty_b.head = Bounds_checked_array<ItemHandle>(head_empty);
  fd_empty_b.tail = b;
  int fd_empty_b_idx = m_orderings->AddFunctionalDependency(thd, fd_empty_b);

  array<ItemHandle, 1> head_a{a};
  FunctionalDependency fd_equiv;
  fd_equiv.type = FunctionalDependency::EQUIVALENCE;
  fd_equiv.head = Bounds_checked_array<ItemHandle>(head_a);
  fd_equiv.tail = b;
  int fd_equiv_idx = m_orderings->AddFunctionalDependency(thd, fd_equiv);

  string trace;
  m_orderings->Build(thd, &trace);
  SCOPED_TRACE(trace);  // Prints out the trace on failure.

  // Start with the empty ordering.
  LogicalOrderings::StateIndex idx = m_orderings->SetOrder(0);
  EXPECT_FALSE(m_orderings->DoesFollowOrder(idx, ab_idx));

  // Now we should get ab simply by means of {} → b, since a is always-active.
  // Note that in a sense, the code here can cheat, because it can reduce ab to
  // b ahead of time if it wants. However, this does not hold for the next test.
  FunctionalDependencySet fds = m_orderings->GetFDSet(fd_empty_b_idx);
  idx = m_orderings->ApplyFDs(idx, fds);
  EXPECT_TRUE(m_orderings->DoesFollowOrder(idx, ab_idx));

  // Restart, then apply a = b. This should give us b.
  idx = m_orderings->SetOrder(0);
  fds = m_orderings->GetFDSet(fd_equiv_idx);
  idx = m_orderings->ApplyFDs(idx, fds);
  EXPECT_TRUE(m_orderings->DoesFollowOrder(idx, b_idx));

  // The always-on FD should have no bitmap, so that we don't waste time trying
  // to follow it at runtime.
  EXPECT_TRUE(m_orderings->GetFDSet(fd_empty_a_idx).none());
  EXPECT_FALSE(m_orderings->GetFDSet(fd_empty_b_idx).none());
}

TEST_F(InterestingOrderingTableTest, FDsFromComputedItems) {
  THD *thd = m_initializer.thd();

  // Add a new item for b + 1.
  Item *bplus1_item =
      new Item_func_plus(new Item_field(m_table->field[1]), new Item_int(1));
  bplus1_item->update_used_tables();
  ItemHandle bplus1 = m_orderings->GetHandle(bplus1_item);

  // The interesting orders are a and a, b + 1.
  array<OrderElement, 1> order_a{OrderElement{a, ORDER_ASC}};
  array<OrderElement, 2> order_ab{OrderElement{a, ORDER_ASC},
                                  OrderElement{bplus1, ORDER_ASC}};
  int a_idx =
      m_orderings->AddOrdering(thd, Ordering(order_a), /*interesting=*/true);
  int ab_idx =
      m_orderings->AddOrdering(thd, Ordering(order_ab), /*interesting=*/true);

  // Add a → b, which is always active.
  array<ItemHandle, 1> head_a{a};
  FunctionalDependency fd_ab;
  fd_ab.type = FunctionalDependency::FD;
  fd_ab.head = Bounds_checked_array<ItemHandle>(head_a);
  fd_ab.tail = b;
  fd_ab.always_active = true;
  int fd_ab_idx = m_orderings->AddFunctionalDependency(thd, fd_ab);

  string trace;
  m_orderings->Build(thd, &trace);
  SCOPED_TRACE(trace);  // Prints out the trace on failure.

  // Start with a. Now we should also have a, b + 1 (there should be
  // an implict b → b + 1 FD), even though b is not in the ordering.
  LogicalOrderings::StateIndex idx = m_orderings->SetOrder(a_idx);
  idx = m_orderings->ApplyFDs(idx, m_orderings->GetFDSet(fd_ab_idx));
  EXPECT_TRUE(m_orderings->DoesFollowOrder(idx, a_idx));
  EXPECT_TRUE(m_orderings->DoesFollowOrder(idx, ab_idx));
}

TEST_F(InterestingOrderingTableTest, MoreOrderedThan) {
  THD *thd = m_initializer.thd();

  // Interesting orders a, ab, c.
  array<OrderElement, 1> order_a{OrderElement{a, ORDER_ASC}};
  array<OrderElement, 2> order_ab{OrderElement{a, ORDER_ASC},
                                  OrderElement{b, ORDER_ASC}};
  array<OrderElement, 1> order_c{OrderElement{c, ORDER_ASC}};
  int a_order_idx =
      m_orderings->AddOrdering(thd, Ordering(order_a), /*interesting=*/true);
  int ab_order_idx =
      m_orderings->AddOrdering(thd, Ordering(order_ab), /*interesting=*/true);
  int c_order_idx =
      m_orderings->AddOrdering(thd, Ordering(order_c), /*interesting=*/true);

  // Add a=c.
  array<ItemHandle, 1> head_a{a};
  FunctionalDependency fd_equiv;
  fd_equiv.type = FunctionalDependency::EQUIVALENCE;
  fd_equiv.head = Bounds_checked_array<ItemHandle>(head_a);
  fd_equiv.tail = c;
  int fd_equiv_idx = m_orderings->AddFunctionalDependency(thd, fd_equiv);

  string trace;
  m_orderings->Build(thd, &trace);
  SCOPED_TRACE(trace);  // Prints out the trace on failure.

  // Start at a and apply a = c, which should give us a and c.
  LogicalOrderings::StateIndex ac_idx = m_orderings->SetOrder(a_order_idx);
  FunctionalDependencySet fds{0};
  fds |= m_orderings->GetFDSet(fd_equiv_idx);
  ac_idx = m_orderings->ApplyFDs(ac_idx, fds);

  LogicalOrderings::StateIndex empty_idx = m_orderings->SetOrder(0);
  LogicalOrderings::StateIndex a_idx = m_orderings->SetOrder(a_order_idx);
  LogicalOrderings::StateIndex ab_idx = m_orderings->SetOrder(ab_order_idx);
  LogicalOrderings::StateIndex c_idx = m_orderings->SetOrder(c_order_idx);

  EXPECT_FALSE(m_orderings->MoreOrderedThan(empty_idx, empty_idx));
  EXPECT_FALSE(m_orderings->MoreOrderedThan(empty_idx, a_idx));
  EXPECT_FALSE(m_orderings->MoreOrderedThan(empty_idx, ab_idx));
  EXPECT_FALSE(m_orderings->MoreOrderedThan(empty_idx, c_idx));
  EXPECT_FALSE(m_orderings->MoreOrderedThan(empty_idx, ac_idx));

  EXPECT_TRUE(m_orderings->MoreOrderedThan(a_idx, empty_idx));
  EXPECT_FALSE(m_orderings->MoreOrderedThan(a_idx, a_idx));
  EXPECT_FALSE(m_orderings->MoreOrderedThan(a_idx, ab_idx));
  EXPECT_TRUE(m_orderings->MoreOrderedThan(a_idx, c_idx));
  EXPECT_FALSE(m_orderings->MoreOrderedThan(a_idx, ac_idx));

  EXPECT_TRUE(m_orderings->MoreOrderedThan(ab_idx, empty_idx));
  EXPECT_TRUE(m_orderings->MoreOrderedThan(ab_idx, a_idx));
  EXPECT_FALSE(m_orderings->MoreOrderedThan(ab_idx, ab_idx));
  EXPECT_TRUE(m_orderings->MoreOrderedThan(ab_idx, c_idx));
  EXPECT_TRUE(m_orderings->MoreOrderedThan(ab_idx, ac_idx));

  EXPECT_TRUE(m_orderings->MoreOrderedThan(c_idx, empty_idx));
  EXPECT_TRUE(m_orderings->MoreOrderedThan(c_idx, a_idx));
  EXPECT_TRUE(m_orderings->MoreOrderedThan(c_idx, ab_idx));
  EXPECT_FALSE(m_orderings->MoreOrderedThan(c_idx, c_idx));
  EXPECT_FALSE(m_orderings->MoreOrderedThan(c_idx, ac_idx));

  EXPECT_TRUE(m_orderings->MoreOrderedThan(ac_idx, empty_idx));
  EXPECT_TRUE(m_orderings->MoreOrderedThan(ac_idx, a_idx));
  EXPECT_TRUE(m_orderings->MoreOrderedThan(ac_idx, ab_idx));
  EXPECT_TRUE(m_orderings->MoreOrderedThan(ac_idx, c_idx));
  EXPECT_FALSE(m_orderings->MoreOrderedThan(ac_idx, ac_idx));
}

TEST_F(InterestingOrderingTableTest, HomogenizedOrderingsAreEquallyGood) {
  THD *thd = m_initializer.thd();

  // Add three tables, with one column each.
  unique_ptr_destroy_only<Fake_TABLE> t1(
      new (thd->mem_root) Fake_TABLE(/*num_columns=*/1, /*nullable=*/true));
  t1->field[0]->field_name = "t1.a";
  ItemHandle t1_a = m_orderings->GetHandle(new Item_field(t1->field[0]));

  unique_ptr_destroy_only<Fake_TABLE> t2(
      new (thd->mem_root) Fake_TABLE(/*num_columns=*/1, /*nullable=*/true));
  t2->field[0]->field_name = "t2.a";
  ItemHandle t2_a = m_orderings->GetHandle(new Item_field(t2->field[0]));

  unique_ptr_destroy_only<Fake_TABLE> t3(
      new (thd->mem_root) Fake_TABLE(/*num_columns=*/1, /*nullable=*/true));
  t3->field[0]->field_name = "t3.a";
  ItemHandle t3_a = m_orderings->GetHandle(new Item_field(t3->field[0]));

  // And t1.a = t2.a.
  array<ItemHandle, 1> head_t1_a{t1_a};
  FunctionalDependency fd_12;
  fd_12.type = FunctionalDependency::EQUIVALENCE;
  fd_12.head = Bounds_checked_array<ItemHandle>(head_t1_a);
  fd_12.tail = t2_a;
  m_orderings->AddFunctionalDependency(thd, fd_12);

  // And t1.a = t3.a.
  FunctionalDependency fd_13;
  fd_13.type = FunctionalDependency::EQUIVALENCE;
  fd_13.head = Bounds_checked_array<ItemHandle>(head_t1_a);
  fd_13.tail = t3_a;
  m_orderings->AddFunctionalDependency(thd, fd_13);

  // Set up the ordering (t1.a). It should be homogenized into (t2.a)
  // and (t3.a) due to the equivalence.
  array<OrderElement, 1> order_a{OrderElement{t1_a, ORDER_ASC}};
  EXPECT_EQ(1, m_orderings->AddOrdering(thd, Ordering{order_a},
                                        /*interesting=*/true));

  string trace;
  m_orderings->Build(thd, &trace);
  SCOPED_TRACE(trace);  // Prints out the trace on failure.

  // Just make sure we have the right indexes.
  ASSERT_EQ(4, m_orderings->num_orderings());
  ASSERT_THAT(m_orderings->ordering(1),
              testing::ElementsAre(OrderElement{t1_a, ORDER_ASC}));
  ASSERT_THAT(m_orderings->ordering(2),
              testing::ElementsAre(OrderElement{t2_a, ORDER_ASC}));
  ASSERT_THAT(m_orderings->ordering(3),
              testing::ElementsAre(OrderElement{t3_a, ORDER_ASC}));
  LogicalOrderings::StateIndex empty_idx = m_orderings->SetOrder(0);
  LogicalOrderings::StateIndex t1a_idx = m_orderings->SetOrder(1);
  LogicalOrderings::StateIndex t2a_idx = m_orderings->SetOrder(2);
  LogicalOrderings::StateIndex t3a_idx = m_orderings->SetOrder(3);

  // (t1.a) is better than both (t2.a) and (t3.a), but the two are,
  // crucially, equivalent to each other.
  EXPECT_TRUE(m_orderings->MoreOrderedThan(t1a_idx, t2a_idx));
  EXPECT_TRUE(m_orderings->MoreOrderedThan(t1a_idx, t3a_idx));

  EXPECT_FALSE(m_orderings->MoreOrderedThan(t2a_idx, t3a_idx));
  EXPECT_FALSE(m_orderings->MoreOrderedThan(t3a_idx, t2a_idx));

  // However, both of them should be more interesting than nothing.
  EXPECT_TRUE(m_orderings->MoreOrderedThan(t2a_idx, empty_idx));
  EXPECT_TRUE(m_orderings->MoreOrderedThan(t3a_idx, empty_idx));
}

TEST_F(InterestingOrderingTableTest, PruneUninterestingOrders) {
  THD *thd = m_initializer.thd();

  unique_ptr_destroy_only<Fake_TABLE> table(
      new (thd->mem_root) Fake_TABLE(/*num_columns=*/3, /*nullable=*/true));
  table->field[0]->field_name = "a";
  table->field[1]->field_name = "b";
  table->field[2]->field_name = "c";

  ItemHandle a = m_orderings->GetHandle(new Item_field(table->field[0]));
  ItemHandle b = m_orderings->GetHandle(new Item_field(table->field[1]));
  ItemHandle c = m_orderings->GetHandle(new Item_field(table->field[2]));

  // Interesting orders are a and bc.
  array<OrderElement, 1> order_a{OrderElement{a, ORDER_ASC}};
  array<OrderElement, 2> order_bc{OrderElement{b, ORDER_ASC},
                                  OrderElement{c, ORDER_ASC}};
  int a_idx =
      m_orderings->AddOrdering(thd, Ordering(order_a), /*interesting=*/true);
  int bc_idx =
      m_orderings->AddOrdering(thd, Ordering(order_bc), /*interesting=*/true);

  // Add b → c.
  array<ItemHandle, 1> head_b{b};
  FunctionalDependency fd_bc;
  fd_bc.type = FunctionalDependency::FD;
  fd_bc.head = Bounds_checked_array<ItemHandle>(head_b);
  fd_bc.tail = c;
  m_orderings->AddFunctionalDependency(thd, fd_bc);

  // Uninteresting orders are b, c and abc. c should be pruned away,
  // since there's no way we can reach anything interesting,
  // but b should be kept, since it could become bc. abc should be
  // shortened and deduplicated into a.
  array<OrderElement, 1> order_b{OrderElement{b, ORDER_ASC}};
  array<OrderElement, 1> order_c{OrderElement{c, ORDER_ASC}};
  array<OrderElement, 3> order_abc{OrderElement{a, ORDER_ASC},
                                   OrderElement{b, ORDER_ASC},
                                   OrderElement{c, ORDER_ASC}};
  int b_idx =
      m_orderings->AddOrdering(thd, Ordering(order_b), /*interesting=*/false);
  int c_idx =
      m_orderings->AddOrdering(thd, Ordering(order_c), /*interesting=*/false);
  int abc_idx =
      m_orderings->AddOrdering(thd, Ordering(order_abc), /*interesting=*/false);

  string trace;
  m_orderings->Build(thd, &trace);
  SCOPED_TRACE(trace);  // Prints out the trace on failure.

  EXPECT_EQ(0, m_orderings->RemapOrderingIndex(c_idx));
  EXPECT_NE(0, m_orderings->RemapOrderingIndex(b_idx));
  EXPECT_NE(m_orderings->RemapOrderingIndex(bc_idx),
            m_orderings->RemapOrderingIndex(b_idx));
  EXPECT_EQ(m_orderings->RemapOrderingIndex(a_idx),
            m_orderings->RemapOrderingIndex(abc_idx));
}
