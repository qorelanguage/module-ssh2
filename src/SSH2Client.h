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

#include <qore/QoreSocket.h>

#include <time.h>

#include <set>

#define DEFAULT_SSH_PORT 22

#define QAUTH_PASSWORD             (1 << 0)
#define QAUTH_KEYBOARD_INTERACTIVE (1 << 1)
#define QAUTH_PUBLICKEY            (1 << 2)

class SSH2Channel;

class SSH2Client : public AbstractPrivateData {
   friend class SSH2Channel;

private:
   typedef std::set<SSH2Channel *> channel_set_t;

  // connection
  char *sshhost;
  uint32_t sshport;
  // authentification
  char *sshuser;
  char *sshpass;
  char *sshkeys_pub;
  char *sshkeys_priv;

  // server info
  const char *sshauthenticatedwith;

  // set of connected channels
  channel_set_t channel_set;
   // socket object for the connection
  QoreSocket socket;

 protected:
   /*
    * close session/connection
    * free ressources
    */
  DLLLOCAL virtual ~SSH2Client();

  DLLLOCAL virtual void deref(ExceptionSink*);
  DLLLOCAL int ssh_connected_unlocked();
  DLLLOCAL int ssh_disconnect_unlocked(int force = 0, ExceptionSink *xsink = 0);
  DLLLOCAL int ssh_connect_unlocked(int timeout_ms, ExceptionSink *xsink);
  DLLLOCAL void channel_deleted_unlocked(SSH2Channel *channel) {
#ifdef DEBUG
     int rc =
#endif
	channel_set.erase(channel);
     assert(rc);
   }

  // the following functions are unlocked so are protected
  DLLLOCAL const char *getHost();
  DLLLOCAL const uint32_t getPort();
  DLLLOCAL const char *getUser();
  DLLLOCAL const char *getPassword();
  DLLLOCAL const char *getKeyPriv();
  DLLLOCAL const char *getKeyPub();
  DLLLOCAL const char *getAuthenticatedWith();
  DLLLOCAL QoreStringNode *fingerprint_unlocked();
  DLLLOCAL const char *get_session_err_unlocked() {
     assert(ssh_session);
     char *msg = 0;
     libssh2_session_last_error(ssh_session, &msg, 0, 0);
     assert(msg);
     return msg;
  }
  DLLLOCAL void do_session_err_unlocked(ExceptionSink *xsink) {
     xsink->raiseException("SSH2-ERROR", get_session_err_unlocked());
  }

  // to ensure thread-safe operations
  QoreThreadLock m;
  LIBSSH2_SESSION *ssh_session;

 public:
  DLLLOCAL SSH2Client(const char*, const uint32_t);
  DLLLOCAL SSH2Client(QoreURL &url, const uint32_t = 0);
  DLLLOCAL int setUser(const char *);
  DLLLOCAL int setPassword(const char *);
  DLLLOCAL int setKeys(const char *, const char *);
  DLLLOCAL QoreStringNode *fingerprint();

  DLLLOCAL int ssh_disconnect(int, ExceptionSink *);
  DLLLOCAL int ssh_connect(int timeout_ms, ExceptionSink *xsink);

  DLLLOCAL int ssh_connected();

  DLLLOCAL QoreObject *register_channel(LIBSSH2_CHANNEL *channel);

  //QoreStringNode *exec(const char *dir, ExceptionSink *xsink);

  DLLLOCAL QoreHashNode *ssh_info(ExceptionSink *xsink);

  DLLLOCAL LIBSSH2_CHANNEL *openSessionChannel(ExceptionSink *xsink) {
     AutoLocker al(m);

     LIBSSH2_CHANNEL *channel = libssh2_channel_open_session(ssh_session);
     if (!channel)
	do_session_err_unlocked(xsink);

     return channel;
  }

};

#endif // _QORE_SSH2CLIENT_H

