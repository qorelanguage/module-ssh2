/*
  modules/ssh2/ssh2-module.h

  SSH2/SFTP integration to QORE

  Copyright 2009 Wolfgang Ritzinger

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef _QORE_SSH2_MODULE_H

#define _QORE_SSH2_MODULE_H

// include configure defines first
#include "../config.h"

// include Qore API
#include <qore/Qore.h>

// include libssh2 API
#include "ssh2.h"

#include <map>

typedef std::map<int, const char*> emap_t;
DLLLOCAL extern emap_t ssh2_emap;

struct ErrDesc {
   const char* err;
   const char* desc;

   DLLLOCAL ErrDesc(const char* e, const char* d) : err(e), desc(d) {
   }
};
typedef std::map<int, ErrDesc> edmap_t;
DLLLOCAL extern edmap_t sftp_emap;

#endif
