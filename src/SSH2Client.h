/* -*- mode: c++; indent-tabs-mode: nil -*- */
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

#include "ssh2-module.h"

#include <qore/QoreSocket.h>

#include <time.h>
#include <stdarg.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <set>
#include <string>

#define DEFAULT_TIMEOUT 2000

DLLLOCAL QoreClass *initSSH2ClientClass(QoreNamespace& ns);
DLLLOCAL extern qore_classid_t CID_SSH2CLIENT;

DLLLOCAL std::string mode2str(const int mode);

#define QAUTH_PASSWORD             (1 << 0)
#define QAUTH_KEYBOARD_INTERACTIVE (1 << 1)
#define QAUTH_PUBLICKEY            (1 << 2)

// 60 second keepalive defaut
#define QKEEPALIVE_DEFAULT  60

DLLLOCAL extern const char *SSH2_ERROR;

class SSH2Channel;
class BlockingHelper;

class SSH2Client : public AbstractPrivateData {
   friend class SSH2Channel;
   friend class BlockingHelper;

private:
   typedef std::set<SSH2Channel *> channel_set_t;

   // connection host
   std::string sshhost, 
      // authentication
      sshuser,
      sshpass,
      sshkeys_pub,
      sshkeys_priv;

   // connection port
   uint32_t sshport;

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

   DLLLOCAL void setKeysIntern();

   DLLLOCAL virtual void deref(ExceptionSink*);

   DLLLOCAL int startup_unlocked();
   DLLLOCAL int ssh_connected_unlocked();
   DLLLOCAL int ssh_disconnect_unlocked(bool force, int timeout_ms = DEFAULT_TIMEOUT, ExceptionSink *xsink = 0);
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
      char* msg = 0;
      libssh2_session_last_error(ssh_session, &msg, 0, 0);
      assert(msg);
      return msg;
   }

   DLLLOCAL void do_session_err_unlocked(ExceptionSink* xsink) {
      xsink->raiseException(SSH2_ERROR, "libssh2 returned error %d: %s", libssh2_session_last_errno(ssh_session), get_session_err_unlocked());
   }

   DLLLOCAL void do_session_err_unlocked(ExceptionSink* xsink, const char *fmt, ...) {
      va_list args;
      QoreStringNode *desc = new QoreStringNode;

      while (true) {
         va_start(args, fmt);
         int rc = desc->vsprintf(fmt, args);
         va_end(args);
         if (!rc)
            break;
      }

      desc->sprintf(": libssh2 returned error %d: %s", libssh2_session_last_errno(ssh_session), get_session_err_unlocked());

      xsink->raiseException(SSH2_ERROR, desc);
   }
   DLLLOCAL void set_blocking_unlocked(bool block) {
      if (ssh_session)
         libssh2_session_set_blocking(ssh_session, (int)block);
   }

   DLLLOCAL int waitsocket_unlocked(ExceptionSink* xsink, const char *toerr, const char *err, const char* m, int timeout_ms = DEFAULT_TIMEOUT_MS) {
      int rc = waitsocket_unlocked(timeout_ms);
      if (!rc) {
         if (xsink)
            xsink->raiseException(toerr, "network timeout after %dms in %s()", timeout_ms, m);
         return -1;
      }
      if (rc < 0) {
         if (xsink)
            xsink->raiseErrnoException(err, errno, "error waiting for network (timeout: %dms) in %s()", timeout_ms, m);
         return -1;
      }
      return 0;
   }

   DLLLOCAL int waitsocket_unlocked(int timeout_ms = DEFAULT_TIMEOUT_MS) {
      return waitsocket_select_unlocked(libssh2_session_block_directions(ssh_session), timeout_ms);
   }

   DLLLOCAL int waitsocket_select_unlocked(int dir, int timeout_ms = DEFAULT_TIMEOUT_MS) {
      assert(ssh_session);

      struct timeval timeout;
      fd_set fd;
      fd_set* writefd = 0;
      fd_set* readfd = 0;
 
      if (timeout_ms >= 0) {
	 timeout.tv_sec = timeout_ms / 1000;
	 timeout.tv_usec = (timeout_ms % 1000) * 1000;
      }

      FD_ZERO(&fd);
 
      FD_SET(socket.getSocket(), &fd);
 
      if (dir & LIBSSH2_SESSION_BLOCK_INBOUND)
	 readfd = &fd;
 
      if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND)
	 writefd = &fd;
 
      //printd(5, "waitsocket_unlocked() sock=%d readfd=%p writefd=%p timeout_ms=%d\n", socket.getSocket() + 1, readfd, writefd, timeout_ms);
      return select(socket.getSocket() + 1, readfd, writefd, 0, timeout_ms >= 0 ? &timeout : 0);
   }

   DLLLOCAL QoreObject *register_channel_unlocked(LIBSSH2_CHANNEL *channel);

   // to ensure thread-safe operations
   QoreThreadLock m;
   LIBSSH2_SESSION* ssh_session;

public:
   DLLLOCAL SSH2Client(const char*, const uint32_t);
   DLLLOCAL SSH2Client(QoreURL &url, const uint32_t = 0);
   DLLLOCAL int setUser(const char *);
   DLLLOCAL int setPassword(const char *);
   DLLLOCAL int setKeys(const char *, const char *, ExceptionSink* xsink);
   DLLLOCAL QoreStringNode *fingerprint();

   DLLLOCAL virtual int connect(int timeout_ms, ExceptionSink *xsink) {
      return ssh_connect(timeout_ms, xsink);
   }
   
   DLLLOCAL virtual int disconnect(bool force = false, int timeout_ms = DEFAULT_TIMEOUT, ExceptionSink *xsink = 0) {
      return ssh_disconnect(force, timeout_ms, xsink);
   }

   DLLLOCAL int ssh_disconnect(bool force = false, int timeout_ms = DEFAULT_TIMEOUT, ExceptionSink *xsink = 0);
   DLLLOCAL int ssh_connect(int timeout_ms, ExceptionSink *xsink);

   DLLLOCAL int ssh_connected();

   DLLLOCAL QoreHashNode *ssh_info();
   DLLLOCAL QoreHashNode *ssh_info_intern();

   DLLLOCAL QoreObject *openSessionChannel(ExceptionSink *xsink, int timeout_ms = -1);
   DLLLOCAL QoreObject *openDirectTcpipChannel(ExceptionSink *xsink, const char *host, int port, const char *shost = "127.0.0.1", int sport = 22, int timeout_ms = -1);
   DLLLOCAL QoreObject *scpGet(ExceptionSink *xsink, const char *path, int timeout_ms = -1, QoreHashNode *statinfo = 0);
   DLLLOCAL QoreObject *scpPut(ExceptionSink *xsink, const char *path, size_t size, int mode = 0644, long mtime = 0, long atime = 0, int timeout_ms = -1);
};

class BlockingHelper {
protected:
   SSH2Client* client;

public:
   DLLLOCAL BlockingHelper(SSH2Client* n_client) : client(n_client) {
      client->set_blocking_unlocked(false);
   }
   DLLLOCAL ~BlockingHelper() {
      client->set_blocking_unlocked(true);
   }
};

#endif // _QORE_SSH2CLIENT_H

