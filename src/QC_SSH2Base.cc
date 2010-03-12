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

void SSH2BASE_constructor(QoreObject *self, const QoreListNode *params, ExceptionSink *xsink) {
   xsink->raiseException("SSH2BASE-CONSTRUCTOR-ERROR", "this class is an abstract class and cannot be instantiated directly");
}

static AbstractQoreNode *SSH2BASE_setUser(QoreObject *self, SSH2Client *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0;

   if(num_params(params) != 1 || !(p0=test_string_param(params, 0))) {
      xsink->raiseException("SSH2BASE-PARAMETER-ERROR", "use setUser(username (string))");
      return 0;
   }

   if (myself->setUser(p0->getBuffer())) {
      xsink->raiseException("SSH2BASE-STATUS-ERROR", "usage of setUser() is not allowed when connected");
      return 0;
   }

   // return error
   return 0;
}

static AbstractQoreNode *SSH2BASE_setPassword(QoreObject *self, SSH2Client *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0;

   if(num_params(params) != 1 || !(p0=test_string_param(params, 0))) {
      xsink->raiseException("SSH2BASE-PARAMETER-ERROR", "use setPassword(password (string))");
      return 0;
   }

   if (myself->setPassword(p0->getBuffer())) {
      xsink->raiseException("SSH2BASE-STATUS-ERROR", "usage of setPassword() is not allowed when connected");
      return 0;
   }

   // return error
   return 0;
}

static AbstractQoreNode *SSH2BASE_setKeys(QoreObject *self, SSH2Client *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0, *p1;
   static const char* ex_param=(char*)"use setKeys(priv_key_file (string), [pub_key_file (string)]). if no pubkey it is priv_key_file.pub";

   if(num_params(params) > 2 || num_params(params) < 1) {
      xsink->raiseException("SSH2BASE-PARAMETER-ERROR", ex_param);
      return 0;
   }

   p0=test_string_param(params, 0);
   p1=test_string_param(params, 1);

   if(!p0) {
      xsink->raiseException("SSH2BASE-PARAMETER-ERROR", ex_param);
      return 0;
   }

   if (myself->setKeys(p0->getBuffer(), p1? p1->getBuffer(): NULL)) {
      xsink->raiseException("SSH2BASE-STATUS-ERROR", "usage of setKeys() is not allowed when connected");
      return 0;
   }

   // return error
   return 0;
}

QoreClass *initSSH2BaseClass() {
   QORE_TRACE("initSSH2Base()");

   QoreClass *QC_SSH2_BASE = new QoreClass("SSH2Base", QDOM_NETWORK);
   CID_SSH2_BASE = QC_SSH2_BASE->getID();
   QC_SSH2_BASE->setConstructor(SSH2BASE_constructor);

   QC_SSH2_BASE->addMethod("setUser",                (q_method_t)SSH2BASE_setUser);
   QC_SSH2_BASE->addMethod("setPassword",            (q_method_t)SSH2BASE_setPassword);
   QC_SSH2_BASE->addMethod("setKeys",                (q_method_t)SSH2BASE_setKeys);

   return QC_SSH2_BASE;
}
