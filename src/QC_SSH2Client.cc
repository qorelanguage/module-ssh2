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

#include "SSH2Client.h"

qore_classid_t CID_SSH2_CLIENT;

// qore-constructor
// SSH2Client(host, [port]);
static void SSH2C_constructor(QoreObject *self, const QoreListNode *params, ExceptionSink *xsink) {
   QORE_TRACE("SSH2C_constructor");

   static char *ex_param=(char*)"use SSH2Client(URL/host (string), [port (int)]; note that providing a port number in the second argument will override any port number given in the URL";

   const QoreStringNode *p0;

   if(num_params(params) > 2 || num_params(params) < 1) {
      xsink->raiseException("SSH2CLIENT-PARAMETER-ERROR", ex_param);
      return;
   }

   if(!(p0 = test_string_param(params, 0))) {
      xsink->raiseException("SSH2CLIENT-PARAMETER-ERROR", ex_param);
      return;
   }

   QoreURL url(p0);

   if (!url.getHost()) {
      xsink->raiseException("SSH2CLIENT-PARAMETER-ERROR", ex_param);
      return;
   }

   if (url.getProtocol() && strcasecmp("ssh", url.getProtocol()->getBuffer()) && strcasecmp("ssh2", url.getProtocol()->getBuffer())) {
      xsink->raiseException("SSH2CLIENT-PARAMETER-ERROR", "URL given in the first argument to SSH2Client::constructor() specifies invalid protocol '%s' (expecting 'ssh' or 'ssh2')", url.getProtocol()->getBuffer());
      return;
   }

   // get optional port number
   const AbstractQoreNode *p1 = get_param(params, 1);
   int port = !is_nothing(p1) ? p1->getAsInt() : 0;

   // create me
   SSH2Client *mySSH2Client = new SSH2Client(url, port);

   self->setPrivate(CID_SSH2_CLIENT, mySSH2Client);
}

// no copy allowed
static void SSH2C_copy(QoreObject *self, QoreObject *old, SSH2Client *myself, ExceptionSink *xsink) {
   xsink->raiseException("SSH2CLIENT-COPY-ERROR", "copying ssh2 connection objects is not allowed");
}

static AbstractQoreNode *SSH2C_connect(QoreObject *self, SSH2Client *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const AbstractQoreNode *p0;
   int to=-1; // default: no timeout

   if(num_params(params) > 1) {
      xsink->raiseException("SSH2CLIENT-PARAMETER-ERROR", "use connect([timeout ms (int)])");
      return 0;
   }

   if((p0=get_param(params, 0)) && p0->getType()!=NT_INT) {
      xsink->raiseException("SSH2CLIENT-PARAMETER-ERROR", "use connect([timeout ms (int)])");
      return 0;
   }
   to=(p0==NULL? -1: p0->getAsInt());

   // connect
   myself->ssh_connect(to, xsink);

   // return error
   return 0;
}

static AbstractQoreNode *SSH2C_disconnect(QoreObject *self, SSH2Client *myself, const QoreListNode *params, ExceptionSink *xsink) {
   if(num_params(params)) {
      xsink->raiseException("SSH2CLIENT-PARAMETER-ERROR", "use disconnect()");
      return 0;
   }

   // connect
   myself->ssh_disconnect(0, xsink);

   // return error
   return 0;
}

static AbstractQoreNode *SSH2C_info(QoreObject *self, SSH2Client *myself, const QoreListNode *params, ExceptionSink *xsink) {
   if(num_params(params)) {
      xsink->raiseException("SSH2CLIENT-PARAMETER-ERROR", "getInfo() does not take any parameter");
      return NULL;
   }

   return myself->ssh_info(xsink);
}

static AbstractQoreNode *SSH2C_openSessionChannel(QoreObject *self, SSH2Client *c, const QoreListNode *params, ExceptionSink *xsink) {
   return c->openSessionChannel(xsink, getMsMinusOneInt(get_param(params, 0)));
}

static AbstractQoreNode *SSH2C_openDirectTcpipChannel(QoreObject *self, SSH2Client *c, const QoreListNode *params, ExceptionSink *xsink) {
   static const char *SSH2CLIENT_OPENDIRECTTCPIPCHANNEL_ERR = "SSH2CLIENT-OPENDIRECTTCPIPCHANNEL-ERROR";
   
   const QoreStringNode *host = test_string_param(params, 0);
   if (!host) {
      xsink->raiseException(SSH2CLIENT_OPENDIRECTTCPIPCHANNEL_ERR, "missing host name for forwarded channel as first argument to SSH2Client::openDirectTcpipChannel()");
      return 0;
   }

   int port = get_int_param(params, 1);
   if (!port) {
      xsink->raiseException(SSH2CLIENT_OPENDIRECTTCPIPCHANNEL_ERR, "missing port number for forwarded channel as second argument to SSH2Client::openDirectTcpipChannel()");
      return 0;
   }

   const QoreStringNode *shost = test_string_param(params, 2);
   int sport = get_int_param(params, 3);

   return c->openDirectTcpipChannel(xsink, host->getBuffer(), port, shost ? shost->getBuffer() : "127.0.0.1", sport ? sport : 22, getMsMinusOneInt(get_param(params, 0)));
}

static AbstractQoreNode *SSH2C_scpGet(QoreObject *self, SSH2Client *c, const QoreListNode *params, ExceptionSink *xsink) {
   static const char *SSH2CLIENT_SCPGET_ERR = "SSH2CLIENT-SCPGET-ERROR";
   
   const QoreStringNode *path = test_string_param(params, 0);
   if (!path) {
      xsink->raiseException(SSH2CLIENT_SCPGET_ERR, "missing remote file path as first argument to SSH2Client::scpGet()");
      return 0;
   }

   const AbstractQoreNode *p = get_param(params, 2);
   if (!is_nothing(p) && p->getType() != NT_REFERENCE) {
      xsink->raiseException(SSH2CLIENT_SCPGET_ERR, "expecting either NOTHING (no argument) or an lvalue reference as the third argument to SSH2Client::scpGet() to return the remote file's status information, got instead type '%s'", p->getTypeName());
      return 0;
   }
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

static AbstractQoreNode *SSH2C_scpPut(QoreObject *self, SSH2Client *c, const QoreListNode *params, ExceptionSink *xsink) {
   static const char *SSH2CLIENT_SCPPUT_ERR = "SSH2CLIENT-SCPPUT-ERROR";
   
   const QoreStringNode *path = test_string_param(params, 0);
   if (!path) {
      xsink->raiseException(SSH2CLIENT_SCPPUT_ERR, "missing remote file path as first argument to SSH2Client::scpPut()");
      return 0;
   }

   int64 size = get_bigint_param(params, 1);
   if (size <= 0) {
      xsink->raiseException(SSH2CLIENT_SCPPUT_ERR, "missing file size as mandatory second argument to SSH2Client::scpPut() (got invalid size %lld)", size);
      return 0;
   }

   int mode = get_int_param(params, 2);
   if (!mode)
      mode = 0644;

   const DateTimeNode *d = test_date_param(params, 3);
   long mtime = d ? d->getEpochSeconds() : 0;
   d = test_date_param(params, 4);
   long atime = d ? d->getEpochSeconds() : 0;
   //printd(5, "SSH2C_scpPut() mtime=%ld atime=%d\n", mtime, atime);

   return c->scpPut(xsink, path->getBuffer(), size, mode, mtime, atime, getMsMinusOneInt(get_param(params, 5)));
}

/**
 * init
 */
QoreClass *initSSH2ClientClass(QoreClass *ssh2base) {
   QORE_TRACE("initSSH2Client()");

   QoreClass *QC_SSH2_CLIENT=new QoreClass("SSH2Client", QDOM_NETWORK);

   QC_SSH2_CLIENT->addBuiltinVirtualBaseClass(ssh2base);

   CID_SSH2_CLIENT=QC_SSH2_CLIENT->getID();
   QC_SSH2_CLIENT->setConstructor(SSH2C_constructor);
   QC_SSH2_CLIENT->setCopy((q_copy_t)SSH2C_copy);

   QC_SSH2_CLIENT->addMethod("connect",                (q_method_t)SSH2C_connect);
   QC_SSH2_CLIENT->addMethod("disconnect",             (q_method_t)SSH2C_disconnect);
   QC_SSH2_CLIENT->addMethod("info",                   (q_method_t)SSH2C_info);
   QC_SSH2_CLIENT->addMethod("openSessionChannel",     (q_method_t)SSH2C_openSessionChannel);
   QC_SSH2_CLIENT->addMethod("openDirectTcpipChannel", (q_method_t)SSH2C_openDirectTcpipChannel);
   QC_SSH2_CLIENT->addMethod("scpGet",                 (q_method_t)SSH2C_scpGet);
   QC_SSH2_CLIENT->addMethod("scpPut",                 (q_method_t)SSH2C_scpPut);

   return QC_SSH2_CLIENT;
}

