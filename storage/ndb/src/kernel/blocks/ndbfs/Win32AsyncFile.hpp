/* 
   Copyright (c) 2007, 2019, Oracle and/or its affiliates. All rights reserved.

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
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA
*/

#ifndef Win32AsyncFile_H
#define Win32AsyncFile_H

/**
 * Win32 Implementation of AsyncFile interface
 */

#include <kernel_types.h>
#include "AsyncFile.hpp"

#define JAM_FILE_ID 395


class Win32AsyncFile : public AsyncFile
{
  friend class Ndbfs;
public:
  Win32AsyncFile(SimulatedBlock& fs);
  virtual ~Win32AsyncFile();

  virtual int init();
  virtual bool isOpen();
  virtual void openReq(Request *request);
  virtual void closeReq(Request *request);
  virtual void syncReq(Request *request);
  virtual void removeReq(Request *request);
  virtual void appendReq(Request *request);
  virtual void rmrfReq(Request *request, const char * path, bool removePath);

  virtual int readBuffer(Request*, char * buf, size_t size, off_t offset);
  virtual int writeBuffer(const char * buf, size_t size, off_t offset);

private:
  void createDirectories();

  HANDLE hFile;
};


#undef JAM_FILE_ID

#endif
