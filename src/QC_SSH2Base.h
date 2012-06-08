/* -*- mode: c++; indent-tabs-mode: nil -*- */
/*
  QC_SSH2Base.h

  libssh2 ssh2 client integration in Qore

  Qore Programming Language

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

#ifndef _QORE_SSH2BASE_H

#define _QORE_SSH2BASE_H

#include "ssh2-module.h"

DLLLOCAL QoreClass* initSSH2BaseClass(QoreNamespace& ns);
DLLLOCAL extern QoreClass* QC_SSH2BASE;

#endif
