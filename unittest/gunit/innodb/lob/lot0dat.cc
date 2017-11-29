/*****************************************************************************

Copyright (c) 2016, 2017 Oracle and/or its affiliates. All Rights Reserved.

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
#include <iostream>
#include <fstream>
#include <map>
#include <string.h>
#include "lot0types.h"

namespace lob_data {

const char* allowed_char = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr"
"stuvwxyz1234567890~!@#$%^&*()_-=+";

static std::map<lobid_t, byte*> g_data;

byte* generate_lob(lobid_t* id, ulint size) {
  lobid_t new_id = g_data.size();
  const ulint max_j = strlen(allowed_char);

  byte* tmp = new byte[size];

  ulint count = 10;
  for (ulint i = 0, j = 0; i < size; ++i, --count) {
    if (count == 0) {
      count = 10;
      ++j;
      if (j == max_j) {
        j = 0;
      }
    }
    tmp[i] = allowed_char[j];
  }
  *id = new_id;

  g_data.insert(std::pair<lobid_t, byte*>(new_id, tmp));
  return(tmp);
}

byte* generate_lob(lobid_t* id, char x, ulint size) {

  lobid_t new_id = g_data.size();
  byte* tmp = new byte[size];

  for (ulint i = 0; i < size; ++i) {
    tmp[i] = x;
  }

  *id = new_id;
  g_data.insert(std::pair<lobid_t, byte*>(new_id, tmp));
  return(tmp);
}

void remove_lob(lobid_t id) {
  auto it = g_data.find(id);

  byte* lob = it->second;
  delete[] lob;

  if (it != g_data.end()) {
    g_data.erase(it);
  }
}

std::pair<byte*, ulint> get_lob(lobid_t* id, const char* filename) {
  std::ifstream fstrm(filename, std::ios_base::in | std::ios_base::binary);
  if (fstrm.fail()) {
    return(std::pair<byte*, ulint>(nullptr, 0));
  }
  fstrm.seekg(0, std::ios_base::end);
  size_t file_size = fstrm.tellg();
  fstrm.seekg(0, std::ios_base::beg);
  byte* tmp = new byte[file_size];
  fstrm.read( (char*) tmp, file_size);
  fstrm.close();
  lobid_t new_id = g_data.size();
  *id = new_id;
  g_data.insert(std::pair<lobid_t, byte*>(new_id, tmp));
  return(std::pair<byte*, ulint>(tmp, file_size));
}

};
