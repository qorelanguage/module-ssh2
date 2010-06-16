/* -*- mode: c++; indent-tabs-mode: nil -*- */
/*
  QC_SSH2Base.h

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

#include "QC_SSH2Base.h"
#include "SSH2Client.h"

qore_classid_t CID_SSH2_BASE;

static const char *SSH2_CONNECTED = "SSH2-CONNECTED";

void SSH2BASE_constructor(QoreObject *self, const QoreListNode *params, ExceptionSink *xsink) {
   xsink->raiseException("SSH2BASE-CONSTRUCTOR-ERROR", "this class is an abstract class and cannot be instantiated directly");
}

// SSH2Client::connect(softint $timeout_ms = -1) returns nothing
// SSH2Client::connect(date $timeout) returns nothing
static AbstractQoreNode *SSH2BASE_connect(QoreObject *self, SSH2Client *myself, const QoreListNode *params, ExceptionSink *xsink) {
   myself->connect(getMsMinusOneInt(get_param(params, 0)), xsink);
   return 0;
}

// SSH2Base::disconnect() returns nothing
static AbstractQoreNode *SSH2BASE_disconnect(QoreObject *self, SSH2Client *myself, const QoreListNode *params, ExceptionSink *xsink) {
   myself->disconnect(0, xsink);
   return 0;
}

// SSH2Base::setUser(string $user) returns nothing
static AbstractQoreNode *SSH2BASE_setUser(QoreObject *self, SSH2Client *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0 = HARD_QORE_STRING(params, 0);

   if (myself->setUser(p0->getBuffer()))
      xsink->raiseException(SSH2_CONNECTED, "usage of SSH2Base::setUser() is not allowed when connected");

   return 0;
}

// SSH2Base::setPassword(string $pass) returns nothing
static AbstractQoreNode *SSH2BASE_setPassword(QoreObject *self, SSH2Client *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0 = HARD_QORE_STRING(params, 0);

   if (myself->setPassword(p0->getBuffer()))
      xsink->raiseException(SSH2_CONNECTED, "usage of SSH2Base::setPassword() is not allowed when connected");

   return 0;
}

// SSH2Base::setKeys(string $priv_key) returns nothing
// SSH2Base::setKeys(string $priv_key, string $pub_key) returns nothing
static AbstractQoreNode *SSH2BASE_setKeys(QoreObject *self, SSH2Client *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0 = HARD_QORE_STRING(params, 0);
   const QoreStringNode *p1 = test_string_param(params, 1);

   if (myself->setKeys(p0->getBuffer(), p1 ? p1->getBuffer() : 0))
      xsink->raiseException(SSH2_CONNECTED, "usage of SSH2Base::setKeys() is not allowed when connected");

   return 0;
}

QoreClass *initSSH2BaseClass() {
   QORE_TRACE("initSSH2Base()");

   QoreClass *QC_SSH2_BASE = new QoreClass("SSH2Base", QDOM_NETWORK);
   CID_SSH2_BASE = QC_SSH2_BASE->getID();
   QC_SSH2_BASE->setConstructor(SSH2BASE_constructor);

   // SSH2Base::connect(softint $timeout_ms = -1) returns nothing
   QC_SSH2_BASE->addMethodExtended("connect",      (q_method_t)SSH2BASE_connect, false, QC_NO_FLAGS, QDOM_DEFAULT, nothingTypeInfo, 1, softBigIntTypeInfo, new QoreBigIntNode(-1));
   // SSH2Base::connect(date $timeout) returns nothing
   QC_SSH2_BASE->addMethodExtended("connect",      (q_method_t)SSH2BASE_connect, false, QC_NO_FLAGS, QDOM_DEFAULT, nothingTypeInfo, 1, dateTypeInfo, QORE_PARAM_NO_ARG);

   // SSH2Base::disconnect() returns nothing
   QC_SSH2_BASE->addMethodExtended("disconnect",   (q_method_t)SSH2BASE_disconnect, false, QC_NO_FLAGS, QDOM_DEFAULT, nothingTypeInfo);

   // SSH2Base::setUser(string $user) returns nothing
   QC_SSH2_BASE->addMethodExtended("setUser",      (q_method_t)SSH2BASE_setUser, false, QC_NO_FLAGS, QDOM_DEFAULT, nothingTypeInfo, 1, stringTypeInfo, QORE_PARAM_NO_ARG);

   // SSH2Base::setPassword(string $pass) returns nothing
   QC_SSH2_BASE->addMethodExtended("setPassword",  (q_method_t)SSH2BASE_setPassword, false, QC_NO_FLAGS, QDOM_DEFAULT, nothingTypeInfo, 1, stringTypeInfo, QORE_PARAM_NO_ARG);

   // SSH2Base::setKeys(string $priv_key) returns nothing
   // SSH2Base::setKeys(string $priv_key, string $pub_key) returns nothing
   QC_SSH2_BASE->addMethodExtended("setKeys",      (q_method_t)SSH2BASE_setKeys, false, QC_NO_FLAGS, QDOM_DEFAULT, nothingTypeInfo, 1, stringTypeInfo, QORE_PARAM_NO_ARG);
   QC_SSH2_BASE->addMethodExtended("setKeys",      (q_method_t)SSH2BASE_setKeys, false, QC_NO_FLAGS, QDOM_DEFAULT, nothingTypeInfo, 2, stringTypeInfo, QORE_PARAM_NO_ARG, stringTypeInfo, QORE_PARAM_NO_ARG);

   return QC_SSH2_BASE;
}
