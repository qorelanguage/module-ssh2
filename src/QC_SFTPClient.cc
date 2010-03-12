/* -*- indent-tabs-mode: nil -*- */
/*
  SFTPClient.h

  libssh2 SFTP client integration into qore

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

#include "SFTPClient.h"

qore_classid_t CID_SFTP_CLIENT;

// qore-class constructor
// SFTPClient([timeout]);
void SFTPC_constructor(QoreObject *self, const QoreListNode *params, ExceptionSink *xsink) {
   QORE_TRACE("SFTPC_constructor");

   static const char *ex_param=(char*)"use SFTPClient(host/URL (string), [port (int)]); note that providing a port number in the second argument will override any port number given in the URL";

   const QoreStringNode *p0;

   if(num_params(params) > 2 || num_params(params) < 1) {
      xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", ex_param);
      return;
   }

   if (!(p0 = test_string_param(params, 0))) {
      xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", ex_param);
      return;
   }

   QoreURL url(p0);

   if (!url.getHost()) {
      xsink->raiseException("SSH2CLIENT-PARAMETER-ERROR", ex_param);
      return;
   }

   if (url.getProtocol() && strcasecmp("sftp", url.getProtocol()->getBuffer())) {
      xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "URL given in the first argument to SFTPClient::constructor() specifies invalid protocol '%s' (expecting 'sftp')", url.getProtocol()->getBuffer());
      return;
   }

   // get optional port number
   const AbstractQoreNode *p1 = get_param(params, 1);
   int port = !is_nothing(p1) ? p1->getAsInt() : 0;

   // create me
   SFTPClient *mySFTPClient = new SFTPClient(url, port);

   /*
     if (*xsink) {
     return;
     }
   */

   /* no init needed. there is only a connect
   // init (creates connection)
   char *errstr=myActiveMQSession->initSession();
   // error?
   if (errstr!=0) {
   xsink->raiseException("AMQ-SESSION-ERROR", "error in constructor: %s", errstr);
   free(errstr);
   return;
   }
   */

   self->setPrivate(CID_SFTP_CLIENT, mySFTPClient);
}

// no copy allowed
void SFTPC_copy(QoreObject *self, QoreObject *old, SFTPClient *myself, ExceptionSink *xsink) {
   xsink->raiseException("SFTPCLIENT-COPY-ERROR", "copying sftp connection objects is not allowed");
}

static AbstractQoreNode *SFTPC_info(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   if (num_params(params)) {
      xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "getInfo() does not take any parameter");
      return 0;
   }

   QoreHashNode *ret = myself->ssh_info(xsink);
   if (!ret) {
      return 0;
   }

   ret->setKeyValue("path", myself->sftppath? new QoreStringNode(myself->sftppath): 0, xsink);

   return ret;
   //  xsink->raiseException("SFTPCLIENT-COPY-ERROR", "copying sftp connection objects is not allowed");
}

static AbstractQoreNode *SFTPC_path(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   if (num_params(params)) {
      xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "use path()");
      return 0;
   }

   //  QoreStringNode *ret=myself->sftp_path(xsink);
   QoreStringNode *ret=myself->sftp_path();
   return ret;
}

static AbstractQoreNode *SFTPC_list(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0=0;

   if ((num_params(params) > 1) ||
      (num_params(params)==1 && !(p0=test_string_param(params, 0)))) {
      xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "use list([directory (string)])");
      return 0;
   }

   QoreHashNode *ret=myself->sftp_list(p0? p0->getBuffer(): 0, xsink);
   return ret;
}

static AbstractQoreNode *SFTPC_stat(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0;

   if (num_params(params) != 1 || !(p0=test_string_param(params, 0))) {
      xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "use stat(filename (string))");
      return 0;
   }

   LIBSSH2_SFTP_ATTRIBUTES attr;

   int rc=myself->sftp_getAttributes(p0->getBuffer(), &attr, xsink);

   if (rc<0) {
      return 0;
   }

   QoreHashNode *ret=new QoreHashNode();
   /*
     #define LIBSSH2_SFTP_ATTR_SIZE              0x00000001
     #define LIBSSH2_SFTP_ATTR_UIDGID            0x00000002
     #define LIBSSH2_SFTP_ATTR_PERMISSIONS       0x00000004
     #define LIBSSH2_SFTP_ATTR_ACMODTIME         0x00000008
     #define LIBSSH2_SFTP_ATTR_EXTENDED          0x80000000
   */

   if (attr.flags & LIBSSH2_SFTP_ATTR_SIZE) {
      ret->setKeyValue("size", new QoreBigIntNode(attr.filesize), xsink);
   }
   if (attr.flags & LIBSSH2_SFTP_ATTR_ACMODTIME) {
      //    ret->setKeyValue("atime", new QoreBigIntNode(attr.atime), xsink);
      //    ret->setKeyValue("mtime", new QoreBigIntNode(attr.mtime), xsink);
      ret->setKeyValue("atime", new DateTimeNode((int64)attr.atime), xsink);
      ret->setKeyValue("mtime", new DateTimeNode((int64)attr.mtime), xsink);
   }
   if (attr.flags & LIBSSH2_SFTP_ATTR_UIDGID) {
      ret->setKeyValue("uid", new QoreBigIntNode(attr.uid), xsink);
      ret->setKeyValue("gid", new QoreBigIntNode(attr.gid), xsink);
   }
   if (attr.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) {
      ret->setKeyValue("permissions", new QoreStringNode(mode2str(attr.permissions)), xsink);
   }
  
   return ret;
}

static AbstractQoreNode *SFTPC_removeFile(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0;
   if (num_params(params)!=1 || !(p0=test_string_param(params, 0))) {
      xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "use removeFile(filename (str))");
      return 0;
   }

   int rc=myself->sftp_unlink(p0->getBuffer(), xsink);
   if (rc < 0) {
      xsink->raiseException("SFTPCLIENT-GENERIC-ERROR", "error in removing file");
      return 0;
   }

   return 0;
}

static AbstractQoreNode *SFTPC_rename(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   static const char* ex_str=(char*)"use rename(oldname (str), newname (str))";

   const QoreStringNode *p0, *p1;
   if (num_params(params)!=2 || !(p0=test_string_param(params, 0)) || !(p1=test_string_param(params, 1))) {
      xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", ex_str);
      return 0;
   }

   // will return 0 on sucess
   int rc=myself->sftp_rename(p0->getBuffer(), p1->getBuffer(), xsink);
   if (rc < 0) {
      xsink->raiseException("SFTPCLIENT-GENERIC-ERROR", "error in renaming entry '%s'", p0->getBuffer());
      return 0;
   }

   return 0; // no return value
}

static AbstractQoreNode *SFTPC_chmod(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0;
   const AbstractQoreNode *p1;
   unsigned int mode;


   if (num_params(params)!=2 || !(p0=test_string_param(params, 0))) {
      xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "use chmod(file (str), mode (octal int))");
      return 0;
   }
  
   if (!(p1=get_param(params, 1)) || p1->getType()!=NT_INT) {
      xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "mode must be a number, eg 0755 or 0644");
      return 0;
   }
   mode=(unsigned int)p1->getAsInt();

   // check if mode is in range
   if (mode != (mode & SFTP_UGOMASK)) {
      xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "mode setting is only possible for user, group and other (no sticky bits)");
      return 0;
   }

   // will return 0 on sucess
   int rc=myself->sftp_chmod(p0->getBuffer(), mode, xsink);
   if (rc < 0) {
      //xsink->raiseException("SFTPCLIENT-GENERIC-ERROR", "error in change mode");
   }

   return 0; // no return value
}

static AbstractQoreNode *SFTPC_getFile(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   /*
     if (!myself->sftp_connected()) {
     xsink->raiseException("SFTPCLIENT-NOT-CONNECTED", "This action can only be performed if the client is connected");
     return 0;
     }
   */

   const QoreStringNode *p0;

   if (num_params(params)!=1 || !(p0=test_string_param(params, 0))) {
      xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "use getFile(file (str))");
      return 0;
   }

   return myself->sftp_getFile(p0->getBuffer(), xsink);

}

static AbstractQoreNode *SFTPC_getTextFile(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0;

   if (num_params(params)!=1 || !(p0=test_string_param(params, 0))) {
      xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "use getFile(file (str))");
      return 0;
   }

   return myself->sftp_getTextFile(p0->getBuffer(), xsink);

}

// putFile(date (binarynode), filename (string), [mode (int,octal)])
static AbstractQoreNode *SFTPC_putFile(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const AbstractQoreNode *p2;
   const QoreStringNode *p1;
   int rc;
   // defaultmode 0644
   int mode=LIBSSH2_SFTP_S_IRUSR|LIBSSH2_SFTP_S_IWUSR|
      LIBSSH2_SFTP_S_IRGRP|
      LIBSSH2_SFTP_S_IROTH;

   if (num_params(params) < 2 || num_params(params) > 3 || !(p1=test_string_param(params, 1))) {
      xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "use putFile(data (binary), filename (string), [mode (octal int)])");
      return 0;
   }
  
   // get the mode if given
   if ((p2=get_param(params, 2))) {
      if (p2->getType()!=NT_INT) {
	 xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "mode must be an octal number, eg 0755");
	 return 0;
      }
      mode=p2->getAsInt();
   }

   // data is a binary node
   const BinaryNode *bn=test_binary_param(params, 0);
   if (!bn) {
      xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "Data must be a Binary object.");
      return 0;
   }

   // transfer the file
   rc=myself->sftp_putFile(bn, p1->getBuffer(), mode, xsink);
   // error?
   if (rc<0) {
      return 0;
   }

   return new QoreBigIntNode(rc);
}

static AbstractQoreNode *SFTPC_mkdir(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0;
   const AbstractQoreNode *p1;
   // defaultmode 0755
   int mode=LIBSSH2_SFTP_S_IRWXU|
      LIBSSH2_SFTP_S_IRGRP|LIBSSH2_SFTP_S_IXGRP|
      LIBSSH2_SFTP_S_IROTH|LIBSSH2_SFTP_S_IXOTH;

   if (!(p0=test_string_param(params, 0)) || num_params(params)<1 || num_params(params)>2) {
      xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "use mkdir(new dir (str), [mode (octal int)])");
      return 0;
   }
  
   if ((p1=get_param(params, 1))) {
      if (p1->getType()!=NT_INT) {
	 xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "mode must be an octal number, eg 0755");
	 return 0;
      }
      mode=p1->getAsInt();
   }

   // will return 0 on sucess
   int rc=myself->sftp_mkdir(p0->getBuffer(), mode, xsink);
   if (rc < 0) {
      xsink->raiseException("SFTPCLIENT-GENERIC-ERROR", "error in creating directory");
   }

   return 0; // no return value
}


static AbstractQoreNode *SFTPC_rmdir(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0;

   if (!(p0=test_string_param(params, 0))) {
      xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "use rmdir(dir to delete (str))");
      return 0;
   }
  
   // will return 0 on sucess
   int rc=myself->sftp_rmdir(p0->getBuffer(), xsink);
   if (rc < 0) {
      xsink->raiseException("SFTPCLIENT-GENERIC-ERROR", "error in removing directory");
   }

   return 0; // no return value
}

// returns NOTHING if the chdir was not working
static AbstractQoreNode *SFTPC_chdir(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0;

   if (!(p0=test_string_param(params, 0))) {
      xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "use chdir(new dir (str))");
      return 0;
   }

   QoreStringNode *ret=myself->sftp_chdir(p0? p0->getBuffer(): 0, xsink);
   return ret;
}

static AbstractQoreNode *SFTPC_connect(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const AbstractQoreNode *p0;
   int to=-1; // default: no timeout

   if (num_params(params) > 1) {
      xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "use connect([timeout ms (int)])");
      return 0;
   }

   if ((p0=get_param(params, 0)) && p0->getType()!=NT_INT) {
      xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "use connect([timeout ms (int)])");
      return 0;
   }
   to = (!p0 ? -1: p0->getAsInt());

   // connect
   myself->sftp_connect(to, xsink);

   // return error
   return 0;
}

static AbstractQoreNode *SFTPC_disconnect(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   if (num_params(params)) {
      xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "use disconnect()");
      return 0;
   }

   // dis connect
   myself->sftp_disconnect(0, xsink);

   // return error
   return 0;
}

/**
 * class init
 */
QoreClass *initSFTPClientClass(QoreClass *ssh2base) {
   QORE_TRACE("initSFTPClient()");

   QoreClass *QC_SFTP_CLIENT=new QoreClass("SFTPClient", QDOM_NETWORK);

   QC_SFTP_CLIENT->addBuiltinVirtualBaseClass(ssh2base);

   CID_SFTP_CLIENT=QC_SFTP_CLIENT->getID();
   QC_SFTP_CLIENT->setConstructor(SFTPC_constructor);
   QC_SFTP_CLIENT->setCopy((q_copy_t)SFTPC_copy);

   QC_SFTP_CLIENT->addMethod("connect", (q_method_t)SFTPC_connect);
   QC_SFTP_CLIENT->addMethod("disconnect", (q_method_t)SFTPC_disconnect);
   QC_SFTP_CLIENT->addMethod("info", (q_method_t)SFTPC_info);

   QC_SFTP_CLIENT->addMethod("path", (q_method_t)SFTPC_path);

   QC_SFTP_CLIENT->addMethod("chdir", (q_method_t)SFTPC_chdir);
   QC_SFTP_CLIENT->addMethod("list", (q_method_t)SFTPC_list);
   QC_SFTP_CLIENT->addMethod("stat", (q_method_t)SFTPC_stat);

   QC_SFTP_CLIENT->addMethod("mkdir", (q_method_t)SFTPC_mkdir);
   QC_SFTP_CLIENT->addMethod("rmdir", (q_method_t)SFTPC_rmdir);

   QC_SFTP_CLIENT->addMethod("removeFile", (q_method_t)SFTPC_removeFile);
   QC_SFTP_CLIENT->addMethod("rename", (q_method_t)SFTPC_rename);
   QC_SFTP_CLIENT->addMethod("chmod", (q_method_t)SFTPC_chmod);

   QC_SFTP_CLIENT->addMethod("putFile", (q_method_t)SFTPC_putFile);
   QC_SFTP_CLIENT->addMethod("getFile", (q_method_t)SFTPC_getFile);
   QC_SFTP_CLIENT->addMethod("getTextFile", (q_method_t)SFTPC_getTextFile);

   return QC_SFTP_CLIENT;
}
