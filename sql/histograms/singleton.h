#ifndef HISTOGRAMS_SINGLETON_INCLUDED
#define HISTOGRAMS_SINGLETON_INCLUDED

/* Copyright (c) 2016, 2017, Oracle and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

/**
  @file sql/histograms/singleton.h
  Singleton histogram.

  This file defines the Singleton histogram. A Singleton histogram is a
  histogram where only a value and it's frequency is stored. It allows us to
  use less storage space, as well as estimating selectivity a bit more
  efficient.

  A singleton histogram converted to a JSON object, follows the following
  "schema":

  {
    // Last time the histogram was updated. As of now, this means "when the
    // histogram was created" (incremental updates are not supported). Date/time
    // is given in UTC.
    // -- J_DATETIME
    "last-updated": "2015-11-04 15:19:51.000000",

    // Histogram type. Always "singleton" for singleton histograms.
    // -- J_STRING
    "histogram-type": "singleton",

    // Fraction of NULL values. This is the total fraction of NULL values in the
    // original data set.
    // -- J_DOUBLE
    "null-values": 0.1,

    // Histogram buckets. May be an empty array, if for instance the source
    // only contains NULL values.
    // -- J_ARRAY
    "buckets":
    [
      [
        // Value
        // -- Data type depends on the source column.
        42,

        // Cumulative frequency
        // -- J_DOUBLE
        0.001978728666831561
      ]
    ]
  }
*/

#include "histogram.h"        // Histogram, Histogram_comparator,
#include "my_decimal.h"
#include "sql_string.h"
#include "thr_malloc.h"
#include "sql/histograms/value_map.h"        // Value_map

#include <stddef.h>
#include <map>                // std::map
#include <string>             // std::string
#include <utility>            // std::pair

#include "my_base.h"          // ha_rows

class Json_array;
class Json_object;
template <class T> class Memroot_allocator;

namespace histograms {

/**
  Singleton histogram.
*/
template <class T>
class Singleton : public Histogram
{
private:
  /// String representation of the histogram type SINGLETON.
  static constexpr const char *singleton_str() { return "singleton"; }

  using singleton_buckets_allocator=
    Memroot_allocator<std::pair<const T, double>>;

  using singleton_buckets_type=
    std::map<const T, double, Histogram_comparator,
             singleton_buckets_allocator>;

  /// The buckets for this histogram [key, cumulative frequency].
  singleton_buckets_type m_buckets;
public:
  /**
    Singleton constructor.

    This will not build the histogram, but only set its properties.

    @param mem_root the mem_root where the histogram contents will be allocated
    @param db_name  name of the database this histogram represents
    @param tbl_name name of the table this histogram represents
    @param col_name name of the column this histogram represents
  */
  Singleton(MEM_ROOT *mem_root, const std::string &db_name,
            const std::string &tbl_name, const std::string &col_name);

  /**
    Singleton copy-constructor

    This will take a copy of the histogram and all of its contents on the
    provided MEM_ROOT.

    @param mem_root the MEM_ROOT to allocate the new histogram on.
    @param other    the histogram to take a copy of
  */
  Singleton(MEM_ROOT *mem_root, const Singleton<T> &other);

  Singleton(const Singleton<T> &other) = delete;

  /**
    Build the Singleton histogram.

    @param   value_map   values to create the histogram for
    @param   num_buckets the number of buckets specified/requested by the user

    @return  true on error, false otherwise
  */
  bool build_histogram(const Value_map<T> &value_map, size_t num_buckets);

  /**
    Convert this histogram to a JSON object.

    This function will take the contents of the current histogram and put
    it in the output parameter "json_object".

    @param[in,out] json_object output where the histogram is to be stored. The
                   caller is responsible for allocating/deallocating the JSON
                   object

    @return        true on error, false otherwise
  */
  bool histogram_to_json(Json_object *json_object) const override;

  /**
    @return number of values/buckets in this histogram
  */
  size_t get_num_buckets() const override { return m_buckets.size(); }

  /**
    Returns the histogram type as a readable string.

    @return a readable string representation of the histogram type
  */
  std::string histogram_type_to_str() const override;

  /**
    Make a clone of this histogram on a MEM_ROOT.

    @param mem_root the MEM_ROOT to allocate the new histogram contents on.

    @return a copy of the histogram allocated on the provided MEM_ROOT.
  */
  Histogram *clone(MEM_ROOT *mem_root) const override;
private:
  /**
    Add value to a JSON bucket

    This function adds the value to the supplied JSON array.

    @param      value       the value to add
    @param[out] json_bucket a JSON array where the bucket data is to be stored

    @return     true on error, false otherwise
  */
  static bool add_value_json_bucket(const T &value,
                                    Json_array *json_bucket);

  /**
    Convert one bucket to a JSON object.

    @param      bucket      the histogram bucket to convert
    @param[out] json_bucket a JSON array where the bucket data is to be stored

    @return     true on error, false otherwise
  */
  static bool create_json_bucket(const std::pair<T, double> &bucket,
                                 Json_array *json_bucket);

protected:
  /**
    Populate this histogram with contents from a JSON object.

    @param json_object a JSON object that represents an Singleton histogram

    @return true on error, false otherwise.
  */
  bool json_to_histogram(const Json_object &json_object) override;
};

} // namespace histograms

#endif
