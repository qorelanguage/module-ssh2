/*
  SSH2Channel.cc

  libssh2 ssh2 channel integration into qore

  Copyright 2010 Wolfgang Ritzinger

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

#include "SSH2Channel.h"

qore_classid_t CID_SSH2_CHANNEL;
QoreClass *QC_SSH2CHANNEL;

void SSH2CHANNEL_constructor(QoreObject *self, const QoreListNode *params, ExceptionSink *xsink) {
   xsink->raiseException("SSH2CHANNEL-CONSTRUCTOR-ERROR", "this class cannot be directly constructed but is created from methods in the SSH2Client class (ex: SSH2Client::openSessionChannel())");
}

// no copy allowed
void SSH2CHANNEL_copy(QoreObject *self, QoreObject *old, SSH2Channel *c, ExceptionSink *xsink) {
  xsink->raiseException("SSH2CHANNEL-COPY-ERROR", "copying SSH2Channel objects is not supported");
}

static void SSH2CHANNEL_destructor(QoreObject *self, SSH2Channel *c, ExceptionSink *xsink) {
   c->destructor();
   c->deref();
}

AbstractQoreNode *SSH2CHANNEL_setenv(QoreObject *self, SSH2Channel *c, const QoreListNode *params, ExceptionSink *xsink) {
   static const char *SSH2CHANNEL_SETENV_ERR = "SSH2CHANNEL-SETENV-ERROR";

   const QoreStringNode *name = test_string_param(params, 0);
   if (!name) {
      xsink->raiseException(SSH2CHANNEL_SETENV_ERR, "expecting a string argument as the first argument to SSH2Channel::setenv() giving the environment variable name to set");
      return 0;
   }

   const QoreStringNode *value = test_string_param(params, 1);
   if (!value) {
      xsink->raiseException(SSH2CHANNEL_SETENV_ERR, "expecting a string argument as the second argument to SSH2Channel::setenv() giving the value of the environment variable to set");
      return 0;
   }

   c->setenv(name->getBuffer(), value->getBuffer(), xsink);
   return 0;
}

AbstractQoreNode *SSH2CHANNEL_requestPty(QoreObject *self, SSH2Channel *c, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *term = test_string_param(params, 0);

   c->requestPty(xsink, term);
   return 0;
}

AbstractQoreNode *SSH2CHANNEL_shell(QoreObject *self, SSH2Channel *c, const QoreListNode *params, ExceptionSink *xsink) {
   c->shell(xsink);
   return 0;
}

AbstractQoreNode *SSH2CHANNEL_eof(QoreObject *self, SSH2Channel *c, const QoreListNode *params, ExceptionSink *xsink) {
   bool b = c->eof(xsink);
   return *xsink ? get_bool_node(b) : 0;
}

AbstractQoreNode *SSH2CHANNEL_sendEof(QoreObject *self, SSH2Channel *c, const QoreListNode *params, ExceptionSink *xsink) {
   c->sendEof(xsink);
   return 0;
}

AbstractQoreNode *SSH2CHANNEL_waitEof(QoreObject *self, SSH2Channel *c, const QoreListNode *params, ExceptionSink *xsink) {
   c->waitEof(xsink);
   return 0;
}

AbstractQoreNode *SSH2CHANNEL_exec(QoreObject *self, SSH2Channel *c, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *command = test_string_param(params, 0);
   if (!command) {
      xsink->raiseException("SSH2CHANNEL-EXEC-ERROR", "missing command string as sole argument to SSH2Channel::exec()");
      return 0;
   }

   c->exec(command->getBuffer(), xsink);
   return 0;
}

AbstractQoreNode *SSH2CHANNEL_read(QoreObject *self, SSH2Channel *c, const QoreListNode *params, ExceptionSink *xsink) {
   return c->read(xsink);
}

AbstractQoreNode *SSH2CHANNEL_readBinary(QoreObject *self, SSH2Channel *c, const QoreListNode *params, ExceptionSink *xsink) {
   return c->readBinary(xsink);
}

AbstractQoreNode *SSH2CHANNEL_readBlock(QoreObject *self, SSH2Channel *c, const QoreListNode *params, ExceptionSink *xsink) {
   int64 size = get_bigint_param(params, 0);
   if (size <= 0) {
      xsink->raiseException("SSH2CHANNEL-READBLOCK-ERROR", "expecting a positive size for the block size to read, got %lld instead; use SSH2Channel::read() to read available data without a block size", size);
      return 0;
   }
   return c->read(size, getMsMinusOneInt(get_param(params, 1)), xsink);
}

AbstractQoreNode *SSH2CHANNEL_readBinaryBlock(QoreObject *self, SSH2Channel *c, const QoreListNode *params, ExceptionSink *xsink) {
   int64 size = get_bigint_param(params, 0);
   if (size <= 0) {
      xsink->raiseException("SSH2CHANNEL-READBINARYBLOCK-ERROR", "expecting a positive size for the block size to read, got %lld instead; use SSH2Channel::readBinary() to read available data without a block size", size);
      return 0;
   }
   return c->readBinary(size, getMsMinusOneInt(get_param(params, 1)), xsink);
}

AbstractQoreNode *SSH2CHANNEL_write(QoreObject *self, SSH2Channel *c, const QoreListNode *params, ExceptionSink *xsink) {
   static const char *SSH2CHANNEL_WRITE_ERROR = "SSH2CHANNEL-WRITE-ERROR";
   const void *buf = 0;
   qore_size_t buflen;

   const AbstractQoreNode *p = get_param(params, 0);
   qore_type_t t = p ? p->getType() : NT_NOTHING;
   if (t != NT_STRING && t != NT_BINARY) {
      xsink->raiseException(SSH2CHANNEL_WRITE_ERROR, "missing string or binary argument as first argument to SSH2Channel::write() (got type '%s')", p ? p->getTypeName() : "NOTHING");
      return 0;
   }

   if (t == NT_STRING) {
      const QoreStringNode *str = reinterpret_cast<const QoreStringNode *>(p);
      buf = str->getBuffer();
      buflen = str->strlen();
   }
   else {
      const BinaryNode *b = reinterpret_cast<const BinaryNode *>(p);
      buf = b->getPtr();
      buflen = b->size();
   }

   // ignore zero-length writes
   if (!buflen)
      return 0;

   int stream = get_int_param(params, 1);
   if (stream < 0) {
      xsink->raiseException(SSH2CHANNEL_WRITE_ERROR, "expecting non-negative integer for stream id as optional second argument to SSH2Channel::write(string|binary, [streamid], [timeout_ms]), got %d instead; use 0 for stdin, 1 for stderr");
      return 0;
   }

   c->write(xsink, buf, buflen, stream, getMsMinusOneInt(get_param(params, 2)));
   return 0;
}

AbstractQoreNode *SSH2CHANNEL_close(QoreObject *self, SSH2Channel *c, const QoreListNode *params, ExceptionSink *xsink) {
   c->close(xsink);
   return 0;
}

AbstractQoreNode *SSH2CHANNEL_waitClosed(QoreObject *self, SSH2Channel *c, const QoreListNode *params, ExceptionSink *xsink) {
   c->waitClosed(xsink);
   return 0;
}

AbstractQoreNode *SSH2CHANNEL_getExitStatus(QoreObject *self, SSH2Channel *c, const QoreListNode *params, ExceptionSink *xsink) {
   int rc = c->getExitStatus(xsink);
   return *xsink ? 0 : new QoreBigIntNode(rc);
}

QoreClass *initSSH2ChannelClass() {
   QORE_TRACE("initSSH2Channel()");

   QC_SSH2CHANNEL = new QoreClass("SSH2Channel", QDOM_NETWORK);
   CID_SSH2_CHANNEL = QC_SSH2CHANNEL->getID();

   QC_SSH2CHANNEL->setConstructor(SSH2CHANNEL_constructor);
   QC_SSH2CHANNEL->setCopy((q_copy_t)SSH2CHANNEL_copy);
   QC_SSH2CHANNEL->setDestructor((q_destructor_t)SSH2CHANNEL_destructor);

   QC_SSH2CHANNEL->addMethod("setenv",          (q_method_t)SSH2CHANNEL_setenv);
   QC_SSH2CHANNEL->addMethod("requestPty",      (q_method_t)SSH2CHANNEL_requestPty);
   QC_SSH2CHANNEL->addMethod("shell",           (q_method_t)SSH2CHANNEL_shell);
   QC_SSH2CHANNEL->addMethod("eof",             (q_method_t)SSH2CHANNEL_eof);
   QC_SSH2CHANNEL->addMethod("sendEof",         (q_method_t)SSH2CHANNEL_sendEof);
   QC_SSH2CHANNEL->addMethod("waitEof",         (q_method_t)SSH2CHANNEL_waitEof);
   QC_SSH2CHANNEL->addMethod("exec",            (q_method_t)SSH2CHANNEL_exec);
   QC_SSH2CHANNEL->addMethod("read",            (q_method_t)SSH2CHANNEL_read);
   QC_SSH2CHANNEL->addMethod("readBlock",       (q_method_t)SSH2CHANNEL_readBlock);
   QC_SSH2CHANNEL->addMethod("readBinary",      (q_method_t)SSH2CHANNEL_readBinary);
   QC_SSH2CHANNEL->addMethod("readBinaryBlock", (q_method_t)SSH2CHANNEL_readBinaryBlock);
   QC_SSH2CHANNEL->addMethod("write",           (q_method_t)SSH2CHANNEL_write);
   QC_SSH2CHANNEL->addMethod("close",           (q_method_t)SSH2CHANNEL_close);
   QC_SSH2CHANNEL->addMethod("waitClosed",      (q_method_t)SSH2CHANNEL_waitClosed);
   QC_SSH2CHANNEL->addMethod("getExitStatus",   (q_method_t)SSH2CHANNEL_getExitStatus);

   return QC_SSH2CHANNEL;
}
