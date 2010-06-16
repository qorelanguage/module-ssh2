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

// SFTPClient::constructor(string $url)
// SFTPClient::constructor(string $host, softint $port)
void SFTPC_constructor(QoreObject *self, const QoreListNode *params, ExceptionSink *xsink) {
   QORE_TRACE("SFTPC_constructor");

   const QoreStringNode *p0 = HARD_QORE_STRING(params, 0);

   QoreURL url(p0);

   if (!url.getHost()) {
      xsink->raiseException("SSH2CLIENT-PARAMETER-ERROR", "no hostname found in URL '%s'", p0->getBuffer());
      return;
   }

   if (url.getProtocol() && strcasecmp("sftp", url.getProtocol()->getBuffer())) {
      xsink->raiseException("SSH2CLIENT-PARAMETER-ERROR", "URL given in the first argument to SFTPClient::constructor() specifies invalid protocol '%s' (expecting 'sftp')", url.getProtocol()->getBuffer());
      return;
   }

   // create private data object
   SSH2Client *mySFTPClient = new SFTPClient(url, get_int_param(params, 1));
   self->setPrivate(CID_SFTP_CLIENT, mySFTPClient);
}

// no copy allowed
void SFTPC_copy(QoreObject *self, QoreObject *old, SFTPClient *myself, ExceptionSink *xsink) {
   xsink->raiseException("SFTPCLIENT-COPY-ERROR", "copying sftp connection objects is not allowed");
}

// SFTPClient::info() returns hash
static AbstractQoreNode *SFTPC_info(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   QoreHashNode *ret = myself->ssh_info(xsink);
   if (ret)
      ret->setKeyValue("path", myself->sftppath? new QoreStringNode(myself->sftppath) : 0, xsink);

   return ret;
}

// SFTPClient::path() returns string|NOTHING
static AbstractQoreNode *SFTPC_path(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   return myself->sftp_path();
}

// SFTPClient::list(string $path) returns hash
static AbstractQoreNode *SFTPC_list_str(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   return myself->sftp_list(HARD_QORE_STRING(params, 0)->getBuffer(), xsink);
}

// SFTPClient::list() returns hash
static AbstractQoreNode *SFTPC_list(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   return myself->sftp_list(0, xsink);
}

static QoreHashNode *attr2hash(const LIBSSH2_SFTP_ATTRIBUTES &attr) {
   QoreHashNode *ret = new QoreHashNode;

   if (attr.flags & LIBSSH2_SFTP_ATTR_SIZE)
      ret->setKeyValue("size", new QoreBigIntNode(attr.filesize), 0);
   if (attr.flags & LIBSSH2_SFTP_ATTR_ACMODTIME) {
      ret->setKeyValue("atime", DateTimeNode::makeAbsolute(currentTZ(), (int64)attr.atime), 0);
      ret->setKeyValue("mtime", DateTimeNode::makeAbsolute(currentTZ(), (int64)attr.mtime), 0);
   }
   if (attr.flags & LIBSSH2_SFTP_ATTR_UIDGID) {
      ret->setKeyValue("uid", new QoreBigIntNode(attr.uid), 0);
      ret->setKeyValue("gid", new QoreBigIntNode(attr.gid), 0);
   }
   if (attr.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS)
      ret->setKeyValue("permissions", new QoreStringNode(mode2str(attr.permissions)), 0);
  
   return ret;
}

// SFTPClient::stat(string $filename) returns any
static AbstractQoreNode *SFTPC_stat(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0 = HARD_QORE_STRING(params, 0);

   LIBSSH2_SFTP_ATTRIBUTES attr;
   int rc = myself->sftp_getAttributes(p0->getBuffer(), &attr, xsink);

   return rc < 0 ? 0 : attr2hash(attr);
}

// SFTPClient::removeFile(string $filename) returns nothing
static AbstractQoreNode *SFTPC_removeFile(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0 = HARD_QORE_STRING(params, 0);

   myself->sftp_unlink(p0->getBuffer(), xsink);
   return 0;
}

// SFTPClient::rename(string $old, string $new) returns nothing
static AbstractQoreNode *SFTPC_rename(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0 = HARD_QORE_STRING(params, 0);
   const QoreStringNode *p1 = HARD_QORE_STRING(params, 1);

   myself->sftp_rename(p0->getBuffer(), p1->getBuffer(), xsink);
   return 0;
}

// SFTPClient::chmod(string $path, int $mode) returns nothing
static AbstractQoreNode *SFTPC_chmod(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0 = HARD_QORE_STRING(params, 0);
   unsigned int mode = HARD_QORE_INT(params, 1);

   // check if mode is in range
   if (mode != (mode & SFTP_UGOMASK)) {
      xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "mode setting is only possible for user, group and other (no sticky bits)");
      return 0;
   }

   myself->sftp_chmod(p0->getBuffer(), mode, xsink);
   return 0;
}

// SFTPClient::getFile(string $path) returns binary
static AbstractQoreNode *SFTPC_getFile(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0 = HARD_QORE_STRING(params, 0);
   return myself->sftp_getFile(p0->getBuffer(), xsink);
}

// SFTPClient::getTextFile(string $path) returns string
static AbstractQoreNode *SFTPC_getTextFile(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0 = HARD_QORE_STRING(params, 0);
   return myself->sftp_getTextFile(p0->getBuffer(), xsink);
}

// SFTPClient::putFile(binary $bin, string $path, int $mode = 0644) returns int
static AbstractQoreNode *SFTPC_putFile_bin(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const BinaryNode *bn = HARD_QORE_BINARY(params, 0);
   const QoreStringNode *p1 = HARD_QORE_STRING(params, 1);
   int mode = HARD_QORE_INT(params, 2);

   // transfer the file
   int rc = myself->sftp_putFile((const char *)bn->getPtr(), bn->size(), p1->getBuffer(), mode, xsink);

   return *xsink ? 0 : new QoreBigIntNode(rc);
}

// SFTPClient::putFile(string $data, string $path, int $mode = 0644) returns int
static AbstractQoreNode *SFTPC_putFile_str(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0 = HARD_QORE_STRING(params, 0);
   const QoreStringNode *p1 = HARD_QORE_STRING(params, 1);
   int mode = HARD_QORE_INT(params, 2);

   // transfer the file
   int rc = myself->sftp_putFile(p0->getBuffer(), p0->strlen(), p1->getBuffer(), mode, xsink);

   return *xsink ? 0 : new QoreBigIntNode(rc);
}

// SFTPClient::mkdir(string $path, int $mode = 0755) returns nothing
static AbstractQoreNode *SFTPC_mkdir(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0 = HARD_QORE_STRING(params, 0);
   int mode = HARD_QORE_INT(params, 1);

   myself->sftp_mkdir(p0->getBuffer(), mode, xsink);

   return 0;
}

// SFTPClient::rmdir(string $path) returns nothing
static AbstractQoreNode *SFTPC_rmdir(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0 = HARD_QORE_STRING(params, 0);

   myself->sftp_rmdir(p0->getBuffer(), xsink);

   return 0;
}

// SFTPClient::chdir(string $path) returns string
static AbstractQoreNode *SFTPC_chdir(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0 = HARD_QORE_STRING(params, 0);

   return myself->sftp_chdir(p0? p0->getBuffer(): 0, xsink);
}

/**
 * class init
 */
QoreClass *initSFTPClientClass(QoreClass *ssh2base) {
   QORE_TRACE("initSFTPClient()");

   QoreClass *QC_SFTP_CLIENT=new QoreClass("SFTPClient", QDOM_NETWORK);

   QC_SFTP_CLIENT->addBuiltinVirtualBaseClass(ssh2base);

   CID_SFTP_CLIENT=QC_SFTP_CLIENT->getID();

   // SFTPClient::constructor(string $url)
   // SFTPClient::constructor(string $host, softint $port)
   QC_SFTP_CLIENT->setConstructorExtended(SFTPC_constructor, false, QC_NO_FLAGS, QDOM_DEFAULT, 1, stringTypeInfo, QORE_PARAM_NO_ARG);
   QC_SFTP_CLIENT->setConstructorExtended(SFTPC_constructor, false, QC_NO_FLAGS, QDOM_DEFAULT, 2, stringTypeInfo, QORE_PARAM_NO_ARG, softBigIntTypeInfo, QORE_PARAM_NO_ARG);

   QC_SFTP_CLIENT->setCopy((q_copy_t)SFTPC_copy);

   // SFTPClient::info() returns hash
   QC_SFTP_CLIENT->addMethodExtended("info",       (q_method_t)SFTPC_info, false, QC_RET_VALUE_ONLY, QDOM_DEFAULT, hashTypeInfo);

   // SFTPClient::path() returns string|NOTHING
   QC_SFTP_CLIENT->addMethodExtended("path",       (q_method_t)SFTPC_path, false, QC_RET_VALUE_ONLY);

   // SFTPClient::list(string $path) returns hash
   QC_SFTP_CLIENT->addMethodExtended("list",       (q_method_t)SFTPC_list_str, false, QC_NO_FLAGS, QDOM_DEFAULT, hashTypeInfo, 1, stringTypeInfo, QORE_PARAM_NO_ARG);
   // SFTPClient::list() returns hash
   QC_SFTP_CLIENT->addMethodExtended("list",       (q_method_t)SFTPC_list, false, QC_NO_FLAGS, QDOM_DEFAULT, hashTypeInfo);

   // SFTPClient::stat(string $filename) returns any
   QC_SFTP_CLIENT->addMethodExtended("stat",       (q_method_t)SFTPC_stat, false, QC_NO_FLAGS, QDOM_DEFAULT, 0, 1, stringTypeInfo, QORE_PARAM_NO_ARG);

   // SFTPClient::removeFile(string $filename) returns nothing
   QC_SFTP_CLIENT->addMethodExtended("removeFile", (q_method_t)SFTPC_removeFile, false, QC_NO_FLAGS, QDOM_DEFAULT, nothingTypeInfo, 1, stringTypeInfo, QORE_PARAM_NO_ARG);

   // SFTPClient::rename(string $old, string $new) returns nothing
   QC_SFTP_CLIENT->addMethodExtended("rename",     (q_method_t)SFTPC_rename, false, QC_NO_FLAGS, QDOM_DEFAULT, nothingTypeInfo, 2, stringTypeInfo, QORE_PARAM_NO_ARG, stringTypeInfo, QORE_PARAM_NO_ARG);

   // SFTPClient::chmod(string $path, int $mode) returns nothing
   QC_SFTP_CLIENT->addMethodExtended("chmod",      (q_method_t)SFTPC_chmod, false, QC_NO_FLAGS, QDOM_DEFAULT, nothingTypeInfo, 2, stringTypeInfo, QORE_PARAM_NO_ARG, bigIntTypeInfo, QORE_PARAM_NO_ARG);

   // SFTPClient::putFile(binary $data, string $path, int $mode = 0644) returns int
   QC_SFTP_CLIENT->addMethodExtended("putFile",    (q_method_t)SFTPC_putFile_bin, false, QC_NO_FLAGS, QDOM_DEFAULT, bigIntTypeInfo, 3, binaryTypeInfo, QORE_PARAM_NO_ARG, stringTypeInfo, QORE_PARAM_NO_ARG, bigIntTypeInfo, new QoreBigIntNode(0644));
   // SFTPClient::putFile(string $data, string $path, int $mode = 0644) returns int
   QC_SFTP_CLIENT->addMethodExtended("putFile",    (q_method_t)SFTPC_putFile_str, false, QC_NO_FLAGS, QDOM_DEFAULT, bigIntTypeInfo, 3, stringTypeInfo, QORE_PARAM_NO_ARG, stringTypeInfo, QORE_PARAM_NO_ARG, bigIntTypeInfo, new QoreBigIntNode(0644));

   // SFTPClient::getFile(string $path) returns binary
   QC_SFTP_CLIENT->addMethodExtended("getFile",    (q_method_t)SFTPC_getFile, false, QC_NO_FLAGS, QDOM_DEFAULT, binaryTypeInfo, 1, stringTypeInfo, QORE_PARAM_NO_ARG);

   // SFTPClient::getTextFile(string $path) returns string
   QC_SFTP_CLIENT->addMethodExtended("getTextFile", (q_method_t)SFTPC_getTextFile, false, QC_NO_FLAGS, QDOM_DEFAULT, stringTypeInfo, 1, stringTypeInfo, QORE_PARAM_NO_ARG);

   // SFTPClient::mkdir(string $path, int $mode = 0755) returns nothing
   QC_SFTP_CLIENT->addMethodExtended("mkdir",       (q_method_t)SFTPC_mkdir, false, QC_NO_FLAGS, QDOM_DEFAULT, bigIntTypeInfo, 2, stringTypeInfo, QORE_PARAM_NO_ARG, bigIntTypeInfo, new QoreBigIntNode(0755));

   // SFTPClient::rmdir(string $path) returns nothing
   QC_SFTP_CLIENT->addMethodExtended("rmdir",       (q_method_t)SFTPC_rmdir, false, QC_NO_FLAGS, QDOM_DEFAULT, nothingTypeInfo, 1, stringTypeInfo, QORE_PARAM_NO_ARG);

   // SFTPClient::chdir(string $path) returns string
   QC_SFTP_CLIENT->addMethodExtended("chdir",       (q_method_t)SFTPC_chdir, false, QC_NO_FLAGS, QDOM_DEFAULT, nothingTypeInfo, 1, stringTypeInfo, QORE_PARAM_NO_ARG);

   return QC_SFTP_CLIENT;
}
