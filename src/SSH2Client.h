/*
  SSH2Client.h

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

#ifndef _QORE_SSH2CLIENT_H

#define _QORE_SSH2CLIENT_H

#include "ssh2.h"

#include <qore/Qore.h>

#include <time.h>



class SSH2Client : public AbstractPrivateData {

 private:
  // connection
  char *sshhost;
  uint32_t sshport;
  // authentification
  char *sshuser;
  char *sshpass;
  char *sshkeys_pub;
  char *sshkeys_priv;

  // server info
  char *sshauthenticatedwith;

  // internal
  int ssh_socket;

 protected:
  DLLLOCAL virtual ~SSH2Client();
  DLLLOCAL virtual void deref(ExceptionSink*);
  DLLLOCAL int ssh_connected_unlocked();
  DLLLOCAL int ssh_disconnect_unlocked(int, ExceptionSink *);
  DLLLOCAL int ssh_connect_unlocked(int timeout_ms, ExceptionSink *xsink);

  // the following functions are unlocked so are protected
  DLLLOCAL const char *getHost();
  DLLLOCAL const uint32_t getPort();
  DLLLOCAL const char *getUser();
  DLLLOCAL const char *getPassword();
  DLLLOCAL const char *getKeyPriv();
  DLLLOCAL const char *getKeyPub();
  DLLLOCAL const char *getAuthenticatedWith();

  // to ensure thread-safe operations
  QoreThreadLock m;
  LIBSSH2_SESSION *ssh_session;

 public:
  DLLLOCAL SSH2Client(const char*, const uint32_t);
  int setUser(const char *);
  int setPassword(const char *);
  int setKeys(const char *, const char *);
  QoreStringNode *fingerprint();

  int ssh_disconnect(int, ExceptionSink *);
  int ssh_connect(int timeout_ms, ExceptionSink *xsink);

  int ssh_connected();

  //QoreStringNode *exec(const char *dir, ExceptionSink *xsink);

  QoreHashNode *ssh_info(ExceptionSink *xsink);

};

#endif // _QORE_SSH2CLIENT_H

