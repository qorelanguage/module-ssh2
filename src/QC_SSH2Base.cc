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

//! @file SSH2Base.qc defines the SSH2Base class

#include "QC_SSH2Base.h"
#include "SSH2Client.h"

qore_classid_t CID_SSH2_BASE;

static const char *SSH2_CONNECTED = "SSH2-CONNECTED";

//! namespace for the SSH2 module
/**# namespace SSH2 {
*/
//! base class for SFTPClient and SSH2Client
/** The SSH2Base class provides common methods to the SSH2Client and SFTPClient classes
 */
/**# class SSH2Base {
public:
 */

//! Throws an exception; the constructor cannot be called manually
/** Throws an exception if called directly; this class cannot be instantiated directly
    @throw SSH2BASE-CONSTRUCTOR-ERROR this class is an abstract class and cannot be instantiated directly or directly inherited by a user-defined class
 */
//# constructor() {}
void SSH2BASE_constructor(QoreObject *self, const QoreListNode *params, ExceptionSink *xsink) {
   xsink->raiseException("SSH2BASE-CONSTRUCTOR-ERROR", "this class is an abstract class and cannot be instantiated directly or directly inherited by a user-defined class");
}

//! connect to remote system
/** Connects to the remote system; if a connection is already established, then it is disconnected first

    @param $timeout an integer giving a timeout in milliseconds or a relative date/time value (ex: \c 15s for 15 seconds)

    @throw SOCKET-CONNECT-ERROR error establishing socket connection (no listener, port blocked, etc); timeout establishing socket connection
    @throw SSH2CLIENT-CONNECT-ERROR no user name set; ssh2 or libssh2 error
    @throw SSH2-ERROR error initializing or establishing ssh2 session
    @throw SSH2CLIENT-AUTH-ERROR no proper authentication method found
    @throw SFTPCLIENT-CONNECT-ERROR error initializing sftp session or getting remote path (exception only possible when called from an SFTPClient object)

    @par Example:
    @code $sftpclient.connect(30s); @endcode
 */
//# nothing connect(timeout $timeout = -1) {}
static AbstractQoreNode *SSH2BASE_connect(QoreObject *self, SSH2Client *myself, const QoreListNode *params, ExceptionSink *xsink) {
   myself->connect(getMsMinusOneInt(get_param(params, 0)), xsink);
   return 0;
}

//! Disconnects from the remote system; throws an exception if the object is not currently connected
/** @throw SSH2CLIENT-NOT-CONNECTED the client is not connected

    @par Example:
    @code $sftpclient.disconnect(); @endcode
 */
//# nothing disconnect() {}
static AbstractQoreNode *SSH2BASE_disconnect(QoreObject *self, SSH2Client *myself, const QoreListNode *params, ExceptionSink *xsink) {
   myself->disconnect(0, xsink);
   return 0;
}

//! Sets the user name for the next connection; can only be called when a connection is not established, otherwise an exception is thrown
/** @param $user the user name to set for the next connection

    @throw SSH2-CONNECTED this method cannot be called when a connection is established

    @par Example:
    @code $sftpclient.setUser("username"); @endcode
 */
//# nothing setUser(string $user) {}
static AbstractQoreNode *SSH2BASE_setUser(QoreObject *self, SSH2Client *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0 = HARD_QORE_STRING(params, 0);

   if (myself->setUser(p0->getBuffer()))
      xsink->raiseException(SSH2_CONNECTED, "usage of SSH2Base::setUser() is not allowed when connected");

   return 0;
}

//! Sets the password for the next connection; can only be called when a connection is not established, otherwise an exception is thrown
/** @param $pass the password to use for the next connection

    @throw SSH2-CONNECTED this method cannot be called when a connection is established

    @par Example:
    @code $sftpclient.setPassword("pass"); @endcode
 */
//# nothing setPassword(string $pass) {}
static AbstractQoreNode *SSH2BASE_setPassword(QoreObject *self, SSH2Client *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0 = HARD_QORE_STRING(params, 0);

   if (myself->setPassword(p0->getBuffer()))
      xsink->raiseException(SSH2_CONNECTED, "usage of SSH2Base::setPassword() is not allowed when connected");

   return 0;
}

//! Sets path to the private key and optionally the public key to use for the next connection; can only be called when a connection is not established, otherwise an exception is thrown
/** @param $priv_key the path to the private key file to use for the next connection
    @param $pub_key optional: the path to the public key file to use for the next connection

    @throw SSH2-CONNECTED this method cannot be called when a connection is established

    @par Example:
    @code $sftpclient.setKeys($ENV.HOME + "/.ssh/id_rsa", $ENV.HOME + "/.ssh/id_rsa.pub"); @endcode
 */
//# nothing setKeys(string $priv_key, *string $pub_key) {}
static AbstractQoreNode *SSH2BASE_setKeys(QoreObject *self, SSH2Client *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0 = HARD_QORE_STRING(params, 0);
   const QoreStringNode *p1 = test_string_param(params, 1);

   if (myself->setKeys(p0->getBuffer(), p1 ? p1->getBuffer() : 0))
      xsink->raiseException(SSH2_CONNECTED, "usage of SSH2Base::setKeys() is not allowed when connected");

   return 0;
}

/**# };
};
*/

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
