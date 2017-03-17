#ifndef HISTOGRAMS_EQUI_HEIGHT_INCLUDED
#define HISTOGRAMS_EQUI_HEIGHT_INCLUDED

/* Copyright (c) 2016, 2017 Oracle and/or its affiliates. All rights reserved.

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
  @file sql/histograms/equi_height.h
  Equi-height histogram.

  This file defines the class representing an equi-height histogram.

  An equi-height histogram converted to a JSON object, follows the following
  "schema":

  {
    // Last time the histogram was updated. As of now, this means "when the
    // histogram was created" (incremental updates are not supported). Date/time
    // is given in UTC.
    // -- J_DATETIME
    "last-updated": "2015-11-04 15:19:51.000000",

    // Histogram type. Always "equi-height" for equi-height histograms.
    // -- J_STRING
    "histogram-type": "equi-height",

    // Fraction of NULL values. This is the total fraction of NULL values in the
    // original data set.
    // -- J_DOUBLE
    "null-values": 0.1,

    // Histogram buckets.  May be an empty array, if for instance the source
    // only contain NULL values.
    // -- J_ARRAY
    "buckets":
    [
      [
        // Lower inclusive value.
        // -- Data type depends on the source column.
        "0",

        // Upper inclusive value.
        // -- Data type depends on the source column.
        "002a38227ecc7f0d952e85ffe37832d3f58910da",

        // Cumulative frequence
        // -- J_DOUBLE
        0.001978728666831561,

        // Number of distinct values in this bucket.
        // -- J_UINT
        10
      ]
    ]
  }
*/

#include <cstddef>                     // size_t
#include <string>                      // std::string
#include <vector>                      // std::vector

#include "equi_height_bucket.h"        // equi_height::Bucket, IWYU pragma: keep
#include "histogram.h"                 // Histogram, value_map_type
#include "my_base.h"                   // ha_rows
#include "sql/histograms/value_map.h"  // Value_map
#include "thr_malloc.h"

class Json_object;
template <class T> class Memroot_allocator;

namespace histograms {

namespace equi_height {
template <class T> class Bucket;
}  // namespace equi_height

template <class T>
class Equi_height : public Histogram
{
private:
  /// String representation of the histogram type EQUI-HEIGHT.
  static constexpr const char *equi_height_str() { return "equi-height"; }

  /// The buckets for this histogram.
  std::vector<equi_height::Bucket<T>,
              Memroot_allocator<equi_height::Bucket<T>> > m_buckets;


  /**
    Create Equi-height buckets from a JSON array.

    This function will add new buckets to the current histogram by going through
    the provided JSON array. Contents are allocated as needed on the current
    histograms MEM_ROOT.

    @param json_bucket a JSON array containing the histogram buckets
    @return true on error, false otherwise
  */
  bool add_bucket_from_json(const Json_array *json_bucket);

protected:
  /**
    Populate this histogram with contents from a JSON object.

    @param json_object a JSON object that represents an Equi-height histogram

    @return true on error, false otherwise.
  */
  bool json_to_histogram(const Json_object &json_object) override;

public:
  /**
    Equi-height constructor.

    This will not build the histogram, but only set its properties.

    @param mem_root the mem_root where the histogram contents will be allocated
    @param db_name  name of the database this histogram represents
    @param tbl_name name of the table this histogram represents
    @param col_name name of the column this histogram represents
  */
  Equi_height(MEM_ROOT *mem_root, const std::string &db_name,
              const std::string &tbl_name, const std::string &col_name);

  /**
    Equi-height copy-constructor

    This will take a copy of the histogram and all of its contents on the
    provided MEM_ROOT.

    @param mem_root the MEM_ROOT to allocate the new histogram on.
    @param other    the histogram to take a copy of
  */
  Equi_height(MEM_ROOT *mem_root, const Equi_height<T> &other);

  Equi_height(const Equi_height<T> &other) = delete;

  /**
    Build the histogram.

    This function will build a new histogram from a "value map". The function
    will create at most num_buckets buckets, but may use less.

    @param  value_map       a value map, where the map key is a value and the
                            map value is the absolute frequency for that value
    @param  num_buckets     maximum number of buckets to create

    @return true on error, false otherwise
  */
  bool build_histogram(const Value_map<T> &value_map, size_t num_buckets);

  /**
    @return number of buckets in this histogram
  */
  size_t get_num_buckets() const override { return m_buckets.size(); }

  /**
    Convert this histogram to a JSON object.

    This function will take the contents of the current histogram and put
    it in the output parameter "json_object".

    @param[in,out] json_object output where the histogram is to be stored The
                   caller is responsible for allocating/deallocating the JSON
                   object

    @return        true on error, false otherwise
  */
  bool histogram_to_json(Json_object *json_object) const override;

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
};

} // namespace histograms

#endif
