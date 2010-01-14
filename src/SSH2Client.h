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
class BlockingHelper;

class SSH2Client : public AbstractPrivateData {
   friend class SSH2Channel;
   friend class BlockingHelper;

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
  DLLLOCAL void set_blocking_unlocked(bool block) {
     assert(ssh_session);
     libssh2_session_set_blocking(ssh_session, (int)block);
  }
  DLLLOCAL int waitsocket_unlocked(int sec = 10, int usec = 0) {
     assert(ssh_session);

     struct timeval timeout;
     fd_set fd;
     fd_set *writefd = 0;
     fd_set *readfd = 0;
 
     timeout.tv_sec = sec;
     timeout.tv_usec = usec;
 
     FD_ZERO(&fd);
 
     FD_SET(socket.getSocket(), &fd);
 
     // now make sure we wait in the correct direction
     int dir = libssh2_session_block_directions(ssh_session);
 
     if (dir & LIBSSH2_SESSION_BLOCK_INBOUND)
	readfd = &fd;
 
     if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND)
	writefd = &fd;
 
     return select(socket.getSocket() + 1, readfd, writefd, 0, &timeout);
  }
  DLLLOCAL QoreObject *register_channel(LIBSSH2_CHANNEL *channel);

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

  DLLLOCAL QoreHashNode *ssh_info(ExceptionSink *xsink);

  DLLLOCAL QoreObject *openSessionChannel(ExceptionSink *xsink) {
     AutoLocker al(m);

     if (!ssh_connected_unlocked()) {
	xsink->raiseException("SSH2CLIENT-OPENSESSIONCHANNEL-ERROR", "cannot call SSH2Client::openSessionChannel() while client is not connected");
	return 0;
     }

     LIBSSH2_CHANNEL *channel = libssh2_channel_open_session(ssh_session);
     if (!channel) {
	do_session_err_unlocked(xsink);
	return 0;
     }

     return register_channel(channel);
  }

   DLLLOCAL QoreObject *openDirectTcpipChannel(ExceptionSink *xsink, const char *host, int port, const char *shost = "127.0.0.1", int sport = 22) {
      AutoLocker al(m);

      if (!ssh_connected_unlocked()) {
	 xsink->raiseException("SSH2CLIENT-OPENSESSIONCHANNEL-ERROR", "cannot call SSH2Client::openDirectTcpipChannel() while client is not connected");
	 return 0;
      }

      LIBSSH2_CHANNEL *channel = libssh2_channel_direct_tcpip_ex(ssh_session, host, port, shost, sport);
      if (!channel) {
	 do_session_err_unlocked(xsink);
	 return 0;
      }

      return register_channel(channel);
   }
};

class BlockingHelper {
protected:
   SSH2Client *client;

public:
   DLLLOCAL BlockingHelper(SSH2Client *n_client) : client(n_client) {
      client->set_blocking_unlocked(false);
   }
   DLLLOCAL ~BlockingHelper() {
      client->set_blocking_unlocked(true);
   }
};

#endif // _QORE_SSH2CLIENT_H

