/* -*- mode: c++; indent-tabs-mode: nil -*- */
/*
  SSH2Client.h

  libssh2 ssh2 client integration in Qore

  Qore Programming Language

  Copyright 2009 Wolfgang Ritzinger
  Copyright (C) 2010 - 2016 Qore Technologies, sro

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
#ifdef _QORE_HAS_QUEUE_OBJECT
#include <qore/QoreQueue.h>
#endif

#include <time.h>
#include <stdarg.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <set>
#include <string>

#ifdef HAVE_POLL_H
#include <poll.h>
#else
// we assume we have select even if sys/select.h is not available (ex: windows)
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#endif

DLLLOCAL QoreClass *initSSH2ClientClass(QoreNamespace& ns);
DLLLOCAL extern qore_classid_t CID_SSH2CLIENT;

DLLLOCAL std::string mode2str(const int mode);

#define QAUTH_PASSWORD             (1 << 0)
#define QAUTH_KEYBOARD_INTERACTIVE (1 << 1)
#define QAUTH_PUBLICKEY            (1 << 2)

// 60 second keepalive defaut
#define QKEEPALIVE_DEFAULT  60

DLLLOCAL extern const char *SSH2_ERROR;
DLLLOCAL extern const char *SSH2_CONNECTED;

class SSH2Channel;
class BlockingHelper;

class AbstractDisconnectionHelper {
public:
   DLLLOCAL ~AbstractDisconnectionHelper() {
   }

   // called before a disconnect
   DLLLOCAL virtual void preDisconnect() = 0;
};

class SSH2Client : public AbstractPrivateData {
   friend class SSH2Channel;
   friend class BlockingHelper;

private:
   typedef std::set<SSH2Channel*> channel_set_t;

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

protected:
   // socket object for the connection
   QoreSocket socket;

   /*
    * close session/connection
    * free ressources
    */
   DLLLOCAL virtual ~SSH2Client();

   DLLLOCAL void setKeysIntern();

   DLLLOCAL virtual void deref(ExceptionSink*);

   DLLLOCAL int startupUnlocked();
   DLLLOCAL int sshConnectedUnlocked();
   DLLLOCAL int sshConnectUnlocked(int timeout_ms, ExceptionSink *xsink);
   DLLLOCAL void channelDeletedUnlocked(SSH2Channel *channel) {
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

   DLLLOCAL QoreStringNode *fingerprintUnlocked();

   DLLLOCAL const char *getSessionErrUnlocked() {
      assert(ssh_session);
      char* msg = 0;
      libssh2_session_last_error(ssh_session, &msg, 0, 0);
      assert(msg);
      return msg;
   }

   DLLLOCAL void doSessionErrUnlocked(ExceptionSink* xsink) {
      xsink->raiseException(SSH2_ERROR, "libssh2 returned error %d: %s", libssh2_session_last_errno(ssh_session), getSessionErrUnlocked());
   }

   DLLLOCAL void doSessionErrUnlocked(ExceptionSink* xsink, const char *fmt, ...) {
      va_list args;
      QoreStringNode *desc = new QoreStringNode;

      while (true) {
         va_start(args, fmt);
         int rc = desc->vsprintf(fmt, args);
         va_end(args);
         if (!rc)
            break;
      }

      desc->sprintf(": libssh2 returned error %d: %s", libssh2_session_last_errno(ssh_session), getSessionErrUnlocked());

      xsink->raiseException(SSH2_ERROR, desc);
   }
   DLLLOCAL void setBlockingUnlocked(bool block) {
      if (ssh_session)
         libssh2_session_set_blocking(ssh_session, (int)block);
   }

   DLLLOCAL int waitSocketUnlocked(ExceptionSink* xsink, const char *toerr, const char *err, const char* m, int timeout_ms = DEFAULT_TIMEOUT_MS, bool in_disconnect = false, AbstractDisconnectionHelper* adh = 0) {
      int rc = waitSocketUnlocked(timeout_ms);
      if (!rc) {
         if (xsink)
            xsink->raiseException(toerr, "network timeout after %dms in %s(); closing connection", timeout_ms, m);
         if (!in_disconnect)
            disconnectUnlocked(true, timeout_ms > DEFAULT_TIMEOUT_MS ? timeout_ms : DEFAULT_TIMEOUT_MS, adh, xsink);
         return -1;
      }
      if (rc < 0) {
         if (xsink)
            xsink->raiseErrnoException(err, errno, "error waiting for network (timeout: %dms) in %s(); closing connection", timeout_ms, m);
         if (!in_disconnect)
            disconnectUnlocked(true, timeout_ms > DEFAULT_TIMEOUT_MS ? timeout_ms : DEFAULT_TIMEOUT_MS, adh, xsink);
         return -1;
      }
      return 0;
   }

   DLLLOCAL int waitSocketUnlocked(int timeout_ms) const {
      return waitSocketUnlocked(libssh2_session_block_directions(ssh_session), timeout_ms);
   }

   DLLLOCAL int waitSocketUnlocked(int dir, int timeout_ms) const {
      return socket.asyncIoWait(timeout_ms, dir & LIBSSH2_SESSION_BLOCK_INBOUND, dir & LIBSSH2_SESSION_BLOCK_OUTBOUND);
   }

   DLLLOCAL QoreObject *registerChannelUnlocked(LIBSSH2_CHANNEL *channel);

   DLLLOCAL virtual int disconnectUnlocked(bool force, int timeout_ms = DEFAULT_TIMEOUT_MS, AbstractDisconnectionHelper* adh = 0, ExceptionSink* xsink = 0);

   // to ensure thread-safe operations
   mutable QoreThreadLock m;
   LIBSSH2_SESSION* ssh_session;

public:
   DLLLOCAL SSH2Client(const char*, const uint32_t);
   DLLLOCAL SSH2Client(QoreURL &url, const uint32_t = 0);
   DLLLOCAL int setUser(const char *);
   DLLLOCAL int setPassword(const char *);
   DLLLOCAL int setKeys(const char *, const char *, ExceptionSink* xsink);
   DLLLOCAL QoreStringNode *fingerprint();

   DLLLOCAL virtual int connect(int timeout_ms, ExceptionSink *xsink) {
      return sshConnect(timeout_ms, xsink);
   }

   DLLLOCAL int disconnect(bool force = false, int timeout_ms = DEFAULT_TIMEOUT_MS, ExceptionSink *xsink = 0) {
      AutoLocker al(m);

      return disconnectUnlocked(force, timeout_ms, 0, xsink);
   }

   DLLLOCAL int sshConnect(int timeout_ms, ExceptionSink *xsink);

   DLLLOCAL int sshConnected();

   DLLLOCAL QoreHashNode *sshInfo();
   DLLLOCAL QoreHashNode *sshInfoIntern();

   DLLLOCAL QoreObject *openSessionChannel(ExceptionSink *xsink, int timeout_ms = -1);
   DLLLOCAL QoreObject *openDirectTcpipChannel(ExceptionSink *xsink, const char *host, int port, const char *shost = "127.0.0.1", int sport = 22, int timeout_ms = -1);
   DLLLOCAL QoreObject *scpGet(ExceptionSink *xsink, const char *path, int timeout_ms = -1, QoreHashNode *statinfo = 0);
   DLLLOCAL QoreObject *scpPut(ExceptionSink *xsink, const char *path, size_t size, int mode = 0644, long mtime = 0, long atime = 0, int timeout_ms = -1);

#ifdef _QORE_HAS_SOCKET_PERF_API
   DLLLOCAL void clearWarningQueue(ExceptionSink* xsink);
   DLLLOCAL void setWarningQueue(ExceptionSink* xsink, int64 warning_ms, int64 warning_bs, Queue* wq, AbstractQoreNode* arg, int64 min_ms = 1000);
   DLLLOCAL QoreHashNode* getUsageInfo() const;
   DLLLOCAL void clearStats();
#endif
};

class BlockingHelper {
protected:
   SSH2Client* client;

public:
   DLLLOCAL BlockingHelper(SSH2Client* n_client) : client(n_client) {
      client->setBlockingUnlocked(false);
   }
   DLLLOCAL ~BlockingHelper() {
      client->setBlockingUnlocked(true);
   }
};

#endif // _QORE_SSH2CLIENT_H
