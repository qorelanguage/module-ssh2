/* -*- mode: c++; indent-tabs-mode: nil -*- */
/*
  SFTPClient.h

  libssh2 SFTP client integration in Qore

  Qore Programming Language

  Copyright (C) 2009 Wolfgang Ritzinger
  Copyright (C) 2010 - 2015 Qore Technologies, sro

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

#ifndef _QORE_SFTPCLIENT_H

#define _QORE_SFTPCLIENT_H

#include "ssh2-module.h"
#include "SSH2Client.h"

#include <qore/Qore.h>
#include <qore/BinaryNode.h>

#include <time.h>
#include <stdarg.h>

#include <string>

DLLLOCAL QoreClass* initSFTPClientClass(QoreNamespace& ns);
DLLLOCAL extern qore_classid_t CID_SFTP_CLIENT;

// the mask for user/group/other permissions
#define SFTP_UGOMASK ((unsigned long)(LIBSSH2_SFTP_S_IRWXU | LIBSSH2_SFTP_S_IRWXG | LIBSSH2_SFTP_S_IRWXO))

class SFTPClient;

class QSftpHelper : public AbstractDisconnectionHelper {
private:
   LIBSSH2_SFTP_HANDLE* sftp_handle;
   SFTPClient* client;
   const char* errstr;
   const char* meth;
   int timeout_ms;
   ExceptionSink* xsink;

   DLLLOCAL int closeIntern();

public:
   DLLLOCAL QSftpHelper(SFTPClient* c, const char* e, const char* m, int to, ExceptionSink* xs) : sftp_handle(0), client(c), errstr(e), meth(m), timeout_ms(to), xsink(xs) {
   }

   DLLLOCAL ~QSftpHelper() {
      if (sftp_handle)
         closeIntern();
   }

   DLLLOCAL int waitSocket();

   DLLLOCAL operator bool() const {
      return (bool)sftp_handle;
   }

   DLLLOCAL LIBSSH2_SFTP_HANDLE* operator*() const {
      return sftp_handle;
   }

   DLLLOCAL void assign(LIBSSH2_SFTP_HANDLE* h) {
      assert(!sftp_handle);
      sftp_handle = h;
   }

   DLLLOCAL void tryClose() {
      if (sftp_handle)
         closeIntern();
   }
   
   DLLLOCAL int close() {
      return closeIntern();
   }

   DLLLOCAL void err(const char* fmt, ...);

   DLLLOCAL virtual void preDisconnect() {
      if (sftp_handle)
         closeIntern();
   }
};

class SFTPClient : public SSH2Client {
   friend class QSftpHelper;
private:

protected:
   DLLLOCAL virtual ~SFTPClient();
   DLLLOCAL virtual void deref(ExceptionSink*);

   DLLLOCAL int sftpConnectedUnlocked();
   DLLLOCAL QoreStringNode *sftpPathUnlocked();
   DLLLOCAL int sftpConnectUnlocked(int timeout_ms, ExceptionSink* xsink);

   DLLLOCAL void doSessionErrUnlocked(ExceptionSink* xsink, QoreStringNode* desc);
   DLLLOCAL void doShutdown(int timeout_ms = DEFAULT_TIMEOUT_MS, ExceptionSink* xsink = 0);

   DLLLOCAL virtual int disconnectUnlocked(bool force, int timeout_ms = DEFAULT_TIMEOUT_MS, AbstractDisconnectionHelper* adh = 0, ExceptionSink* xsink = 0);
   
public:
   // session props
   std::string sftppath;

   LIBSSH2_SFTP* sftp_session;

   DLLLOCAL SFTPClient(const char*, const uint32_t);
   DLLLOCAL SFTPClient(QoreURL& url, const uint32_t = 0);

   DLLLOCAL virtual int connect(int timeout_ms, ExceptionSink* xsink) {
      return sftpConnect(timeout_ms, xsink);
   }
   
   DLLLOCAL int sftpConnect(int timeout_ms, ExceptionSink* xsink = 0);

   DLLLOCAL int sftpConnected();

   //DLLLOCAL QoreStringNode *sftpPath(ExceptionSink* xsink);
   DLLLOCAL QoreStringNode *sftpPath();
   DLLLOCAL QoreStringNode *sftpChdir(const char* nwd, int timeout_ms, ExceptionSink* xsink);
   DLLLOCAL QoreHashNode *sftpList(const char* path, int timeout_ms, ExceptionSink* xsink);
   DLLLOCAL QoreListNode *sftpListFull(const char* path, int timeout_ms, ExceptionSink* xsink);
   DLLLOCAL int sftpMkdir(const char* dir, const int mode, int timeout_ms, ExceptionSink* xsink);
   DLLLOCAL int sftpRmdir(const char* dir, int timeout_ms, ExceptionSink* xsink);
   DLLLOCAL int sftpRename(const char* from, const char* to, int timeout_ms, ExceptionSink* xsink);
   DLLLOCAL int sftpUnlink(const char* file, int timeout_ms, ExceptionSink* xsink);
   DLLLOCAL int sftpChmod(const char* file, const int mode, int timeout_ms, ExceptionSink* xsink);

   DLLLOCAL BinaryNode *sftpGetFile(const char* file, int timeout_ms, ExceptionSink* xsink);
   DLLLOCAL QoreStringNode *sftpGetTextFile(const char* file, int timeout_ms, const QoreEncoding *encoding, ExceptionSink* xsink);
   DLLLOCAL qore_size_t sftpPutFile(const char* data, qore_size_t len, const char* fname, int mode, int timeout_ms, ExceptionSink* xsink);

   DLLLOCAL int sftpGetAttributes(const char* fname, LIBSSH2_SFTP_ATTRIBUTES *attrs, int timeout_ms, ExceptionSink* xsink);

   DLLLOCAL QoreHashNode *sftpInfo();
};

// maybe this should go to ssh2-module.h?
extern AbstractQoreNode *SSH2C_setUser(QoreObject*, SSH2Client*, const QoreListNode*, ExceptionSink*);
extern AbstractQoreNode *SSH2C_setPassword(QoreObject*, SSH2Client*, const QoreListNode*, ExceptionSink*);
extern AbstractQoreNode *SSH2C_setKeys(QoreObject*, SSH2Client*, const QoreListNode*, ExceptionSink*);

static inline std::string absolute_filename(const SFTPClient* me, const char* f) {
   if (!f)
      return std::string();

   // absolute path
   if (f[0] == '/')
      return std::string(f);

   // all other cases: put the sftppath in front
   return me->sftppath + "/" + f;
}

#endif // _QORE_SFTPCLIENT_H

