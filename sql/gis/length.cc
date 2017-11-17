// Copyright (c) 2017, Oracle and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License along with
// this program; if not, write to the Free Software Foundation, 51 Franklin
// Street, Suite 500, Boston, MA 02110-1335 USA.

/// @file
///
/// This file implements the length functor and function.

#include <cmath>  // std::isfinite

#include <boost/geometry.hpp>
#include "my_inttypes.h"                            // MYF
#include "my_sys.h"                                 // my_error
#include "mysqld_error.h"                           // Error codes
#include "sql/dd/types/spatial_reference_system.h"  // dd::Spatial_reference_system
#include "sql/gis/geometries.h"
#include "sql/gis/geometries_traits.h"
#include "sql/gis/length.h"
#include "sql/gis/length_functor.h"
#include "sql/sql_exception_handler.h"  // handle_gis_exception

namespace bg = boost::geometry;
namespace bgs = boost::geometry::srs;
namespace bgsd = boost::geometry::strategy::distance;

namespace gis {
Length::Length(double major, double minor)
    : m_geographic_strategy(new bgsd::andoyer<bgs::spheroid<double>>(
          bgs::spheroid<double>(major, minor))) {}

double Length::operator()(const Geometry &g1) const { return apply(*this, g1); }

double Length::eval(const Geometry &) const {
  DBUG_ASSERT(false); /* purecov: inspected */
  throw std::exception();
}

double Length::eval(const Geographic_linestring &g1) const {
  return bg::length(g1, *m_geographic_strategy);
}

double Length::eval(const Cartesian_linestring &g1) const { return bg::length(g1); }

/////////////////////////////////////////////////////////////////////////////

double Length::eval(const Geographic_multilinestring &g1) const {
  return bg::length(g1, *m_geographic_strategy);
}

double Length::eval(const Cartesian_multilinestring &g1) const {
  return bg::length(g1);
}
/////////////////////////////////////////////////////////////////////////////

bool length(const dd::Spatial_reference_system *srs, const Geometry *g1,
            double *length, bool *null) noexcept {
  try {
    DBUG_ASSERT(srs == nullptr ||
                ((srs->is_cartesian() &&
                  g1->coordinate_system() == Coordinate_system::kCartesian) ||
                 (srs->is_geographic() &&
                  g1->coordinate_system() == Coordinate_system::kGeographic)));

    if ((*null = (g1->is_empty()))) return false;

    if ((g1->type() != Geometry_type::kLinestring) &&
        (g1->type() != Geometry_type::kMultilinestring)) {
      *null = true;
      return false;
    }

    Length len(srs ? srs->semi_major_axis() : 0.0,
               srs ? srs->semi_minor_axis() : 0.0);
    *length = len(*g1);
  } catch (...) {
    handle_gis_exception("st_length");
    return true;
  }

  if (!std::isfinite(*length) || *length < 0.0) {
    my_error(ER_DATA_OUT_OF_RANGE, MYF(0), "Length", "st_length");
    return true;
  }

  return false;
}

}  // namespace gis
