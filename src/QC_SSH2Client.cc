/* -*- indent-tabs-mode: nil -*- */
/*
  QC_SSH2Client.cc

  libssh2 ssh2 client integration into qore

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

//! @file SSH2Client.qc defines the SSH2Client class

#include "SSH2Client.h"

qore_classid_t CID_SSH2_CLIENT;

//! namespace for the SSH2 module
/**# namespace SSH2 {
*/
//! allows Qore programs to establish an ssh2 connection to a remote server
/** 
 */
/**# class SSH2Client inherits SSH2Base {
public:
 */

//! creates the object with the given URL
/** @param $url The URL to use to connect to the remote server; if any protocol (URI scheme) is present, then it must be \c "ssh" or \c "ssh2"; with this variant the username and password can be set as well as the hostname and port

    @throw SSH2CLIENT-PARAMETER-ERROR unknown protocol passed in URL; no hostname in URL

    @par Example:
    @code my $ssh2client SSH2Client("ssh2://user:pass@host:port"); @endcode
 */
//# constructor(string $url) {}

//! creates the object with the given hostname and port number
/** @param $host the remote host to connect to
    @param $port the port number on the remote host to connect to

    @throw SSH2CLIENT-PARAMETER-ERROR empty hostname passed

    @par Example:
    @code my $ssh2client SSH2Client("host", 4022); @endcode
 */
//# constructor(string $host, softint $port) {}
static void SSH2C_constructor(QoreObject *self, const QoreListNode *params, ExceptionSink *xsink) {
   QORE_TRACE("SSH2C_constructor");

   const QoreStringNode *p0 = HARD_QORE_STRING(params, 0);

   QoreURL url(p0);

   if (!url.getHost()) {
      xsink->raiseException("SSH2CLIENT-PARAMETER-ERROR", "no hostname found in URL '%s'", p0->getBuffer());
      return;
   }

   if (url.getProtocol() && strcasecmp("ssh", url.getProtocol()->getBuffer()) && strcasecmp("ssh2", url.getProtocol()->getBuffer())) {
      xsink->raiseException("SSH2CLIENT-PARAMETER-ERROR", "URL given in the first argument to SSH2Client::constructor() specifies invalid protocol '%s' (expecting 'ssh' or 'ssh2')", url.getProtocol()->getBuffer());
      return;
   }

   // create private data object
   SSH2Client *mySSH2Client = new SSH2Client(url, get_int_param(params, 1));
   self->setPrivate(CID_SSH2_CLIENT, mySSH2Client);
}

//! throws an exception; currently SSH2Client objects cannot be copied
/** @throw SSH2CLIENT-COPY-ERROR copying SSH2Client objects is not currently implemented
 */
//# SSH2Client copy() {}
static void SSH2C_copy(QoreObject *self, QoreObject *old, SSH2Client *myself, ExceptionSink *xsink) {
   xsink->raiseException("SSH2CLIENT-COPY-ERROR", "copying ssh2 connection objects is not allowed");
}

//! returns a hash with information about the current connection status
/** this method is safe to call when not connected

    @return a hash with the following keys:
    - \c ssh2host: (string) the host name of the remote server
    - \c ssh2port: (int) the port number of the remote server
    - \c ssh2user: (string) the user name used for the connection
    - \c keyfile_priv: (string) the filename of the local private key file used
    - \c keyfile_pub: (string) the filename of the local public key file used
    - \c fingerprint: (*string) The fingerprint of the public host key of the remote server as a string of hex digit pairs separated by colons (:), ex: \c "AC:AA:DF:3F:49:82:5A:1A:DE:C9:ED:14:00:7D:65:9E" or \c NOTHING if not connected
    - \c authenticated: (*string) a string giving the authentication mechanism used: \c "publickey", \c "password", \c "keyboard-interactive" or \c NOTHING if not connected
    - \c connected: (bool) tells if the connection is currently active or not
    - \c methods: (hash) a hash of strings giving the crytographic methods used for the connection

    @par Example:
    @code my hash $h = $ssh2client.info(); @endcode
 */
//# hash info() {}
static AbstractQoreNode *SSH2C_info(QoreObject *self, SSH2Client *myself, const QoreListNode *params, ExceptionSink *xsink) {
   return myself->ssh_info();
}

//! Opens a login session and returns a SSH2Channel object for the session
/** @param $timeout an integer giving a timeout in milliseconds or a relative date/time value (ex: \c 15s for 15 seconds)

    @throw SSH2CLIENT-NOT-CONNECTED client is not connected
    @throw SSH2CLIENT-TIMEOUT timeout opening channel
    @throw SSH2-ERROR error opening channel

    @par Example:
    @code my SSH2Channel $chan = $ssh2client.openSessionChannel(30s); @endcode
 */
//# SSH2Channel openSessionChannel(timeout $timeout = -1) {}
static AbstractQoreNode *SSH2C_openSessionChannel(QoreObject *self, SSH2Client *c, const QoreListNode *params, ExceptionSink *xsink) {
   return c->openSessionChannel(xsink, getMsMinusOneInt(get_param(params, 0)));
}

//! Opens a port forwarding channel and returns the corresponding SSH2Channel object for the new forwarded connection
/** @param $host the remote host to connect to
    @param $port the port number on the remote host to connect to
    @param $source_host the host name to report as the source of the connection
    @param $source_port the port number to report as the source of the connection
    @param $timeout an integer giving a timeout in milliseconds or a relative date/time value (ex: \c 15s for 15 seconds)

    @throw SSH2CLIENT-OPENDIRECTTCPIPCHANNEL-ERROR port number for forwarded channel as second argument cannot be zero; source port number as fourth argument cannot be zero
    @throw SSH2CLIENT-NOT-CONNECTED client is not connected
    @throw SSH2CLIENT-TIMEOUT timeout opening channel
    @throw SSH2-ERROR error opening channel

    @par Example:
    @code my SS2Channel $chan = $ssh2client.("host", 4022, NOTHING, NOTHING, 30s); @endcode
 */
//# SSH2Channel openDirectTcpipChannel(string $host, softint $port, string $source_host = "127.0.0.1", softint $source_port = 22, timeout $timeout = -1) {}
static AbstractQoreNode *SSH2C_openDirectTcpipChannel(QoreObject *self, SSH2Client *c, const QoreListNode *params, ExceptionSink *xsink) {
   static const char *SSH2CLIENT_OPENDIRECTTCPIPCHANNEL_ERR = "SSH2CLIENT-OPENDIRECTTCPIPCHANNEL-ERROR";
   
   const QoreStringNode *host = HARD_QORE_STRING(params, 0);

   int port = get_int_param(params, 1);
   if (!port) {
      xsink->raiseException(SSH2CLIENT_OPENDIRECTTCPIPCHANNEL_ERR, "port number for forwarded channel as second argument to SSH2Client::openDirectTcpipChannel() cannot be zero");
      return 0;
   }

   const QoreStringNode *shost = HARD_QORE_STRING(params, 2);
   int sport = get_int_param(params, 3);
   if (!sport) {
      xsink->raiseException(SSH2CLIENT_OPENDIRECTTCPIPCHANNEL_ERR, "source port number as fourth argument to SSH2Client::openDirectTcpipChannel() cannot be zero");
      return 0;
   }

   return c->openDirectTcpipChannel(xsink, host->getBuffer(), port, shost ? shost->getBuffer() : "127.0.0.1", sport ? sport : 22, getMsMinusOneInt(get_param(params, 4)));
}

//! opens a channel for retrieving a remote file with an optional timeout value and an optional reference for returning file status information
/** an SSH2Channel object is returned to use to retrieve the file's data

    @throw SSH2CLIENT-NOT-CONNECTED client is not connected
    @throw SSH2CLIENT-TIMEOUT timeout opening channel
    @throw SSH2-ERROR error opening channel

    @par Example:
    @code
my hash $info;
my SS2Channel $chan = $ssh2client.scpGet("/tmp/file.txt", 30s, \$info); @endcode
 */
//# SSH2Channel scpGet(string $path, timeout $timeout = -1, *reference $statinfo) {}
static AbstractQoreNode *SSH2C_scpGet(QoreObject *self, SSH2Client *c, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *path = HARD_QORE_STRING(params, 0);

   const AbstractQoreNode *p = get_param(params, 2);
   const ReferenceNode *ref = p ? reinterpret_cast<const ReferenceNode *>(p) : 0;   

   ReferenceHolder<QoreHashNode> statinfo(ref ? new QoreHashNode : 0, xsink);

   ReferenceHolder<QoreObject> o(c->scpGet(xsink, path->getBuffer(), getMsMinusOneInt(get_param(params, 1)), *statinfo), xsink);
   if (o && ref) {
      AutoVLock vl(xsink);
      ReferenceHelper rh(ref, vl, xsink);
      if (!rh || rh.assign(statinfo.release(), xsink))
	 return 0;
   }
   return o.release();
}

//! Opens a channel for sending a file to the remote server; an SSH2Channel object is returned to use to send the file's data
/** @param $remote_path the path of the file to save on the remote server
    @param $size the size of the file to send; this parameter is required
    @param $mode the file's mode on the remote machine
    @param $mtime the file's last modified time to create on the remote machine
    @param $atime the file's last access time to create on the remote machine
    @param $timeout an integer giving a timeout in milliseconds or a relative date/time value (ex: \c 15s for 15 seconds)

    @throw SSH2CLIENT-NOT-CONNECTED client is not connected
    @throw SSH2CLIENT-TIMEOUT timeout opening channel
    @throw SSH2-ERROR error opening channel

    @par Example:
    @code my SS2Channel $chan = $ssh2client.scpPut("/tmp/file.txt", $size, 0644, 2010-12-25, 2010-12-25, 30s); @endcode
 */
//# SSH2Channel scpPut(string $remote_path, softint $size, softint $mode = 0644, date $mtime = date(), date $atime = date(), timeout $timeout = -1) {}
static AbstractQoreNode *SSH2C_scpPut(QoreObject *self, SSH2Client *c, const QoreListNode *params, ExceptionSink *xsink) {
   static const char *SSH2CLIENT_SCPPUT_ERR = "SSH2CLIENT-SCPPUT-ERROR";
   
   const QoreStringNode *path = HARD_QORE_STRING(params, 0);

   int64 size = HARD_QORE_INT(params, 1);
   if (size <= 0) {
      xsink->raiseException(SSH2CLIENT_SCPPUT_ERR, "invalid file size as second argument to SSH2Client::scpPut() (got invalid size %lld)", size);
      return 0;
   }

   int mode = HARD_QORE_INT(params, 2);

   const DateTimeNode *d = HARD_QORE_DATE(params, 3);
   long mtime = d->getEpochSeconds();

   d = HARD_QORE_DATE(params, 4);
   long atime = d->getEpochSeconds();
   //printd(5, "SSH2C_scpPut() mtime=%ld atime=%d\n", mtime, atime);

   return c->scpPut(xsink, path->getBuffer(), size, mode, mtime, atime, getMsMinusOneInt(get_param(params, 5)));
}

/**# };
};
*/

/**
 * init
 */
QoreClass *initSSH2ClientClass(QoreClass *ssh2base, const QoreClass *SSH2Channel) {
   QORE_TRACE("initSSH2Client()");

   QoreClass *QC_SSH2_CLIENT = new QoreClass("SSH2Client", QDOM_NETWORK);

   QC_SSH2_CLIENT->addBuiltinVirtualBaseClass(ssh2base);

   CID_SSH2_CLIENT=QC_SSH2_CLIENT->getID();

   // SSH2Client::constructor(string $url)
   // SSH2Client::constructor(string $host, softint $port);
   QC_SSH2_CLIENT->setConstructorExtended(SSH2C_constructor, false, QC_NO_FLAGS, QDOM_DEFAULT, 1, stringTypeInfo, QORE_PARAM_NO_ARG);
   QC_SSH2_CLIENT->setConstructorExtended(SSH2C_constructor, false, QC_NO_FLAGS, QDOM_DEFAULT, 2, stringTypeInfo, QORE_PARAM_NO_ARG, softBigIntTypeInfo, QORE_PARAM_NO_ARG);

   QC_SSH2_CLIENT->setCopy((q_copy_t)SSH2C_copy);

   // SSH2Client::info() returns hash
   QC_SSH2_CLIENT->addMethodExtended("info",                   (q_method_t)SSH2C_info, false, QC_RET_VALUE_ONLY, QDOM_DEFAULT, hashTypeInfo);

   // SSH2Client::openSessionChannel(softint $timeout_ms = -1) returns SSH2Channel
   QC_SSH2_CLIENT->addMethodExtended("openSessionChannel",     (q_method_t)SSH2C_openSessionChannel, false, QC_NO_FLAGS, QDOM_DEFAULT, SSH2Channel->getTypeInfo(), 1, softBigIntTypeInfo, new QoreBigIntNode(-1));
   // SSH2Client::openSessionChannel(date $timeout) returns SSH2Channel
   QC_SSH2_CLIENT->addMethodExtended("openSessionChannel",     (q_method_t)SSH2C_openSessionChannel, false, QC_NO_FLAGS, QDOM_DEFAULT, SSH2Channel->getTypeInfo(), 1, dateTypeInfo, QORE_PARAM_NO_ARG);

   // SSH2Client::openDirectTcpipChannel(string $host, softint $port, string $source_host = "127.0.0.1", softint $source_port = 22, softint $timeout_ms = -1) returns SSH2Channel
   QC_SSH2_CLIENT->addMethodExtended("openDirectTcpipChannel", (q_method_t)SSH2C_openDirectTcpipChannel, false, QC_NO_FLAGS, QDOM_DEFAULT, SSH2Channel->getTypeInfo(), 5, stringTypeInfo, QORE_PARAM_NO_ARG, softBigIntTypeInfo, QORE_PARAM_NO_ARG, stringTypeInfo, new QoreStringNode("127.0.0.1"), softBigIntTypeInfo, new QoreBigIntNode(22), softBigIntTypeInfo, new QoreBigIntNode(-1));
   // SSH2Client::openDirectTcpipChannel(string $host, softint $port, string $source_host = "127.0.0.1", softint $source_port = 22, date $timeout) returns SSH2Channel
   QC_SSH2_CLIENT->addMethodExtended("openDirectTcpipChannel", (q_method_t)SSH2C_openDirectTcpipChannel, false, QC_NO_FLAGS, QDOM_DEFAULT, SSH2Channel->getTypeInfo(), 5, stringTypeInfo, QORE_PARAM_NO_ARG, softBigIntTypeInfo, QORE_PARAM_NO_ARG, stringTypeInfo, new QoreStringNode("127.0.0.1"), softBigIntTypeInfo, new QoreBigIntNode(22), dateTypeInfo, QORE_PARAM_NO_ARG);

   // SSH2Client::scpGet(string $path, softint $timeout_ms = -1) returns SSH2Channel
   QC_SSH2_CLIENT->addMethodExtended("scpGet",                 (q_method_t)SSH2C_scpGet, false, QC_NO_FLAGS, QDOM_DEFAULT, SSH2Channel->getTypeInfo(), 2, stringTypeInfo, QORE_PARAM_NO_ARG, softBigIntTypeInfo, new QoreBigIntNode(-1));
   // SSH2Client::scpGet(string $path, date $timeout) returns SSH2Channel
   QC_SSH2_CLIENT->addMethodExtended("scpGet",                 (q_method_t)SSH2C_scpGet, false, QC_NO_FLAGS, QDOM_DEFAULT, SSH2Channel->getTypeInfo(), 2, stringTypeInfo, QORE_PARAM_NO_ARG, dateTypeInfo, QORE_PARAM_NO_ARG);
   // SSH2Client::scpGet(string $path, softint $timeout_ms = -1, reference $statinfo) returns SSH2Channel
   QC_SSH2_CLIENT->addMethodExtended("scpGet",                 (q_method_t)SSH2C_scpGet, false, QC_NO_FLAGS, QDOM_DEFAULT, SSH2Channel->getTypeInfo(), 3, stringTypeInfo, QORE_PARAM_NO_ARG, softBigIntTypeInfo, new QoreBigIntNode(-1), referenceTypeInfo, QORE_PARAM_NO_ARG);
   // SSH2Client::scpGet(string $path, date $timeout, reference $statinfo) returns SSH2Channel
   QC_SSH2_CLIENT->addMethodExtended("scpGet",                 (q_method_t)SSH2C_scpGet, false, QC_NO_FLAGS, QDOM_DEFAULT, SSH2Channel->getTypeInfo(), 3, stringTypeInfo, QORE_PARAM_NO_ARG, dateTypeInfo, QORE_PARAM_NO_ARG, referenceTypeInfo, QORE_PARAM_NO_ARG);

   // SSH2Client::scpPut(string $remote_path, softint $size, softint $mode = 0644, date $mtime = date(), date $atime = date(), softint $timeout_ms = -1) returns SSH2Channel
   QC_SSH2_CLIENT->addMethodExtended("scpPut",                 (q_method_t)SSH2C_scpPut, false, QC_NO_FLAGS, QDOM_DEFAULT, SSH2Channel->getTypeInfo(), 6, stringTypeInfo, QORE_PARAM_NO_ARG, softBigIntTypeInfo, QORE_PARAM_NO_ARG, softBigIntTypeInfo, new QoreBigIntNode(0644), dateTypeInfo, new DateTimeNode, dateTypeInfo, new DateTimeNode, softBigIntTypeInfo, new QoreBigIntNode(-1));
   // SSH2Client::scpPut(string $remote_path, softint $size, softint $mode = 0644, date $mtime = date(), date $atime = date(), date $timeout) returns SSH2Channel
   QC_SSH2_CLIENT->addMethodExtended("scpPut",                 (q_method_t)SSH2C_scpPut, false, QC_NO_FLAGS, QDOM_DEFAULT, SSH2Channel->getTypeInfo(), 6, stringTypeInfo, QORE_PARAM_NO_ARG, softBigIntTypeInfo, QORE_PARAM_NO_ARG, softBigIntTypeInfo, new QoreBigIntNode(0644), dateTypeInfo, new DateTimeNode, dateTypeInfo, new DateTimeNode, dateTypeInfo, QORE_PARAM_NO_ARG);

   return QC_SSH2_CLIENT;
}

