/* -*- mode: c++; indent-tabs-mode: nil -*- */
/*
  SFTPClient.h

  libssh2 SFTP client integration in Qore

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

#ifndef _QORE_SFTPCLIENT_H

#define _QORE_SFTPCLIENT_H

#include "ssh2-module.h"
#include "SSH2Client.h"

#include <qore/Qore.h>
#include <qore/BinaryNode.h>

#include <time.h>

DLLLOCAL QoreClass *initSFTPClientClass(QoreClass *parent);
DLLLOCAL extern qore_classid_t CID_SFTP_CLIENT;

// the mask for user/group/other permissions
#define SFTP_UGOMASK ((unsigned long)(LIBSSH2_SFTP_S_IRWXU | LIBSSH2_SFTP_S_IRWXG | LIBSSH2_SFTP_S_IRWXO))

class SFTPClient : public SSH2Client {
private:

protected:
   DLLLOCAL virtual ~SFTPClient();
   DLLLOCAL virtual void deref(ExceptionSink*);

   DLLLOCAL int sftp_connected_unlocked();
   DLLLOCAL QoreStringNode *sftp_path_unlocked();
   int sftp_connect_unlocked(int timeout_ms, ExceptionSink *xsink);
   int sftp_disconnect_unlocked(bool force, ExceptionSink *xsink = 0);

public:
   // session props
   char *sftppath;
   char *sftpauthenticatedwith;

   LIBSSH2_SFTP *sftp_session;

   DLLLOCAL SFTPClient(const char*, const uint32_t);
   DLLLOCAL SFTPClient(QoreURL &url, const uint32_t = 0);

   DLLLOCAL virtual int connect(int timeout_ms, ExceptionSink *xsink) {
      return sftp_connect(timeout_ms, xsink);
   }
   
   DLLLOCAL virtual int disconnect(bool force = false, ExceptionSink *xsink = 0) {
      return sftp_disconnect(force, xsink);
   }

   int sftp_disconnect(bool force = false, ExceptionSink *xsink = 0);
   int sftp_connect(int timeout_ms, ExceptionSink *xsink = 0);

   int sftp_connected();

   //QoreStringNode *sftp_path(ExceptionSink *xsink);
   QoreStringNode *sftp_path();
   QoreStringNode *sftp_chdir(const char *nwd, ExceptionSink *xsink);
   QoreHashNode *sftp_list(const char *path, ExceptionSink *xsink);
   int sftp_mkdir(const char *dir, const int mode, ExceptionSink *xsink);
   int sftp_rmdir(const char *dir, ExceptionSink *xsink);
   int sftp_rename(const char *from, const char *to, ExceptionSink *xsink);
   int sftp_unlink(const char *file, ExceptionSink *xsink);
   int sftp_chmod(const char *file, const int mode, ExceptionSink *xsink);

   BinaryNode *sftp_getFile(const char *file, ExceptionSink *xsink = 0);
   QoreStringNode *sftp_getTextFile(const char *file, ExceptionSink *xsink);
   int sftp_putFile(const BinaryNode *data, const char *fname, int mode, class ExceptionSink *xsink);

   int sftp_getAttributes(const char *fname, LIBSSH2_SFTP_ATTRIBUTES *attrs, ExceptionSink *xsink);

   QoreHashNode *sftp_info(ExceptionSink *xsink);

};

// maybe this should go to ssh2-module.h?
extern class AbstractQoreNode *SSH2C_setUser(class QoreObject *, class SSH2Client *, const QoreListNode *, class ExceptionSink *);
extern class AbstractQoreNode *SSH2C_setPassword(class QoreObject *, class SSH2Client *, const QoreListNode *, class ExceptionSink *);
extern class AbstractQoreNode *SSH2C_setKeys(class QoreObject *, class SSH2Client *, const QoreListNode *, class ExceptionSink *);

static inline std::string absolute_filename(const SFTPClient *me, const char *f) {
   if(!f) {
      return NULL;
   }
   // absolute path
   if(f && f[0]=='/') {
      return std::string(f);
   }
   // all other cases: put the sftppath in front
   return std::string(me->sftppath)+"/"+std::string(f);
}

static inline int str2mode(const std::string perms) {
   int mode=0;

   // let the modestring be sth like:
   // ugo+rwx[,...]

   return mode;
}

static inline std::string mode2str(const int mode) {
   std::string ret=std::string("----------");
   int tmode=mode;
   for(int i=2; i>=0; i--) {
      if(tmode & 001) {
	 ret[1+2+i*3]='x';
      }
      if(tmode & 002) {
	 ret[1+1+i*3]='w';
      }
      if(tmode & 004) {
	 ret[1+0+i*3]='r';
      }
      tmode>>=3;
   }
#ifdef S_ISDIR
   if(S_ISDIR(mode)) {
      ret[0]='d';
   }
#endif
#ifdef S_ISBLK
   if(S_ISBLK(mode)) {
      ret[0]='b';
   }
#endif
#ifdef S_ISCHR
   if(S_ISCHR(mode)) {
      ret[0]='c';
   }
#endif
//#ifdef S_ISREG
//  if(S_ISREG(mode)) {
//    ret[0]='r';
//  }
//#endif
#ifdef S_ISFIFO
   if(S_ISFIFO(mode)) {
      ret[0]='p';
   }
#endif
#ifdef S_ISLNK
   if(S_ISLNK(mode)) {
      ret[0]='l';
   }
#endif
#ifdef S_ISSOCK
   if(S_ISSOCK(mode)) {
      ret[0]='s';
   }
#endif

   return ret;
}

#endif // _QORE_SFTPCLIENT_H

