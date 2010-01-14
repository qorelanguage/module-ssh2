/*
  SSH2Channel.cc

  libssh2 ssh2 channel integration in Qore

  Qore Programming Language

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
#include "SSH2Client.h"

void SSH2Channel::destructor() {
   // close channel and deregister from parent
   AutoLocker al(parent->m);
   if (channel) {
      parent->channel_deleted_unlocked(this);
      close_unlocked();
   }
}

int SSH2Channel::setenv(const char *name, const char *value, ExceptionSink *xsink) {
   AutoLocker al(parent->m);
   if (check_open(xsink))
      return -1;

   int rc;
   if ((rc = libssh2_channel_setenv(channel, (char *)name, value)))
      parent->do_session_err_unlocked(xsink);

   return rc;
}

static QoreString vanilla("vanilla");

int SSH2Channel::requestPty(ExceptionSink *xsink, const QoreString *term, const QoreString *modes, int width, int height, int width_px, int height_px) {
   AutoLocker al(parent->m);
   if (check_open(xsink))
      return -1;

   if (!term)
      term = &vanilla;

   int rc = libssh2_channel_request_pty_ex(channel, term->getBuffer(), term->strlen(), modes ? modes->getBuffer() : 0, modes ? modes->strlen() : 0, width, height, width_px, height_px);
   if (rc)
      parent->do_session_err_unlocked(xsink);

   return rc;
}

int SSH2Channel::shell(ExceptionSink *xsink) {
   AutoLocker al(parent->m);
   if (check_open(xsink))
      return -1;

   int rc = libssh2_channel_shell(channel);
   if (rc)
      parent->do_session_err_unlocked(xsink);

   return rc;
}

bool SSH2Channel::eof(ExceptionSink *xsink) {
   AutoLocker al(parent->m);
   if (check_open(xsink))
      return -1;

   return (bool)libssh2_channel_eof(channel);
}

int SSH2Channel::waitEof(ExceptionSink *xsink) {
   AutoLocker al(parent->m);
   if (check_open(xsink))
      return 0;

   int rc = libssh2_channel_wait_eof(channel);
   if (rc < 0)
      parent->do_session_err_unlocked(xsink);

   return rc;
}

int SSH2Channel::sendEof(ExceptionSink *xsink) {
   AutoLocker al(parent->m);
   if (check_open(xsink))
      return -1;

   int rc = libssh2_channel_send_eof(channel);
   if (rc)
      parent->do_session_err_unlocked(xsink);

   return rc;
}

int SSH2Channel::exec(const char *command, ExceptionSink *xsink) {
   AutoLocker al(parent->m);
   if (check_open(xsink))
      return -1;

   int rc = libssh2_channel_exec(channel, command);
   //printd(5, "SSH2Channel::exec() cmd=%s rc=%d\n", command, rc);
   if (rc)
      parent->do_session_err_unlocked(xsink);

   return rc;
}

#define QSSH2_BUFSIZE 4096

QoreStringNode *SSH2Channel::read(ExceptionSink *xsink) {
   AutoLocker al(parent->m);
   if (check_open(xsink))
      return 0;

   QoreStringNodeHolder str(new QoreStringNode);

   BlockingHelper bh(parent);

   qore_offset_t rc;
   bool first = true;
   do {
     loop0:
      char buffer[QSSH2_BUFSIZE];
      rc = libssh2_channel_read(channel, buffer, QSSH2_BUFSIZE);

      //printd(5, "SSH2Channel::read() rc=%lld (EAGAIN=%d)\n", rc, LIBSSH2_ERROR_EAGAIN);
      if (rc > 0)
	 str->concat(buffer, rc);
      else if (rc == LIBSSH2_ERROR_EAGAIN && !str->strlen() && first) {
	 first = false;
	 parent->waitsocket_unlocked();
	 goto loop0;
      }
   }
   while (rc > 0);

   if (rc < 0 && rc != LIBSSH2_ERROR_EAGAIN) {
      parent->do_session_err_unlocked(xsink);
      return 0;
   }

   return str.release();
}

BinaryNode *SSH2Channel::readBinary(ExceptionSink *xsink) {
   AutoLocker al(parent->m);
   if (check_open(xsink))
      return 0;

   SimpleRefHolder<BinaryNode> bin(new BinaryNode);

   BlockingHelper bh(parent);

   qore_offset_t rc;
   bool first = true;
   do {
     loop0:
      char buffer[QSSH2_BUFSIZE];
      rc = libssh2_channel_read(channel, buffer, QSSH2_BUFSIZE);

      //printd(5, "SSH2Channel::read() rc=%lld (EAGAIN=%d)\n", rc, LIBSSH2_ERROR_EAGAIN);
      if (rc > 0)
	 bin->append(buffer, rc);
      else if (rc == LIBSSH2_ERROR_EAGAIN && !bin->size() && first) {
	 first = false;
	 parent->waitsocket_unlocked();
	 goto loop0;
      }
   }
   while (rc > 0);

   if (rc < 0 && rc != LIBSSH2_ERROR_EAGAIN) {
      parent->do_session_err_unlocked(xsink);
      return 0;
   }

   return bin.release();
}

int SSH2Channel::write(ExceptionSink *xsink, const void *buf, qore_size_t buflen, int stream_id) {
   AutoLocker al(parent->m);
   if (check_open(xsink))
      return 0;

   int rc = libssh2_channel_write_ex(channel, stream_id, (char *)buf, buflen);
   if (rc < 0)
      parent->do_session_err_unlocked(xsink);

   return rc;
}

int SSH2Channel::close(ExceptionSink *xsink) {
   AutoLocker al(parent->m);
   if (check_open(xsink))
      return 0;

   int rc = libssh2_channel_close(channel);
   if (rc < 0)
      parent->do_session_err_unlocked(xsink);

   return rc;
}

int SSH2Channel::waitClosed(ExceptionSink *xsink) {
   AutoLocker al(parent->m);
   if (check_open(xsink))
      return 0;

   int rc = libssh2_channel_wait_closed(channel);
   if (rc < 0)
      parent->do_session_err_unlocked(xsink);

   return rc;
}

int SSH2Channel::getExitStatus(ExceptionSink *xsink) {
   AutoLocker al(parent->m);
   if (check_open(xsink))
      return 0;

   return libssh2_channel_get_exit_status(channel);
}
