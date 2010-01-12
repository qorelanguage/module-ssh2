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

#include <qore/Qore.h>
#include "ssh2.h"
#include "SSH2Client.h"
#include "SFTPClient.h"
#include "SSH2Channel.h"

// module def
QoreStringNode *ssh2_module_init();
void ssh2_module_ns_init(class QoreNamespace *rns, class QoreNamespace *qns);
void ssh2_module_delete();

// ssh2 client class def
DLLLOCAL class QoreClass *initSSH2ClientClass();
DLLLOCAL extern qore_classid_t CID_SSH2_CLIENT;

// sftp client class def
DLLLOCAL class QoreClass *initSFTPClientClass();
DLLLOCAL extern qore_classid_t CID_SFTP_CLIENT;

#endif

