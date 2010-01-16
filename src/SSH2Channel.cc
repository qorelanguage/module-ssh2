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

int SSH2Channel::setenv(const char *name, const char *value, int timeout_ms, ExceptionSink *xsink) {
   AutoLocker al(parent->m);
   if (check_open(xsink))
      return -1;

   BlockingHelper bh(parent);

   int rc;
   while (true) {
      rc = libssh2_channel_setenv(channel, (char *)name, value);
      if (rc == LIBSSH2_ERROR_EAGAIN) {
	 if ((rc = parent->check_timeout(timeout_ms, "SSH2CHANNEL-SETENV-TIMEOUT", "SSH2CHANNEL-SETENV-ERROR", xsink)))
	    break;
	 continue;
      }
      if (rc)
	 parent->do_session_err_unlocked(xsink);
      break;
   }

   return rc;
}

static QoreString vanilla("vanilla");

int SSH2Channel::requestPty(ExceptionSink *xsink, const QoreString *term, const QoreString *modes, int width, int height, int width_px, int height_px, int timeout_ms) {
   AutoLocker al(parent->m);
   if (check_open(xsink))
      return -1;

   if (!term)
      term = &vanilla;

   BlockingHelper bh(parent);

   int rc;
   while (true) {
      rc = libssh2_channel_request_pty_ex(channel, term->getBuffer(), term->strlen(), modes ? modes->getBuffer() : 0, modes ? modes->strlen() : 0, width, height, width_px, height_px);
      if (rc == LIBSSH2_ERROR_EAGAIN) {
	 if ((rc = parent->check_timeout(timeout_ms, "SSH2CHANNEL-REQUESTPTY-TIMEOUT", "SSH2CHANNEL-REQUESTPTY-ERROR", xsink)))
	    break;
	 continue;
      }
      if (rc)
	 parent->do_session_err_unlocked(xsink);
      break;
   }

   return rc;
}

int SSH2Channel::shell(ExceptionSink *xsink, int timeout_ms) {
   AutoLocker al(parent->m);
   if (check_open(xsink))
      return -1;

   BlockingHelper bh(parent);

   int rc;
   while (true) {
      rc = libssh2_channel_shell(channel);
      if (rc == LIBSSH2_ERROR_EAGAIN) {
	 if ((rc = parent->check_timeout(timeout_ms, "SSH2CHANNEL-SHELL-TIMEOUT", "SSH2CHANNEL-SHELL-ERROR", xsink)))
	    break;
	 continue;
      }
      if (rc)
	 parent->do_session_err_unlocked(xsink);
      break;
   }

   return rc;
}

bool SSH2Channel::eof(ExceptionSink *xsink) {
   AutoLocker al(parent->m);
   if (check_open(xsink))
      return true;

   return (bool)libssh2_channel_eof(channel);
}

int SSH2Channel::waitEof(ExceptionSink *xsink, int timeout_ms) {
   AutoLocker al(parent->m);
   if (check_open(xsink))
      return -1;

   BlockingHelper bh(parent);

   int rc;
   while (true) {
      rc = libssh2_channel_wait_eof(channel);
      if (rc == LIBSSH2_ERROR_EAGAIN) {
	 if ((rc = parent->check_timeout(timeout_ms, "SSH2CHANNEL-WAITEOF-TIMEOUT", "SSH2CHANNEL-WAITEOF-ERROR", xsink)))
	    break;
	 continue;
      }
      if (rc)
	 parent->do_session_err_unlocked(xsink);
      break;
   }

   return rc;
}

int SSH2Channel::sendEof(ExceptionSink *xsink, int timeout_ms) {
   AutoLocker al(parent->m);
   if (check_open(xsink))
      return -1;

   BlockingHelper bh(parent);

   int rc;
   while (true) {
      rc = libssh2_channel_send_eof(channel);
      if (rc == LIBSSH2_ERROR_EAGAIN) {
	 if ((rc = parent->check_timeout(timeout_ms, "SSH2CHANNEL-SENDEOF-TIMEOUT", "SSH2CHANNEL-SENDEOF-ERROR", xsink)))
	    break;
	 continue;
      }
      if (rc)
	 parent->do_session_err_unlocked(xsink);
      break;
   }

   return rc;
}

int SSH2Channel::exec(const char *command, int timeout_ms, ExceptionSink *xsink) {
   AutoLocker al(parent->m);
   if (check_open(xsink))
      return -1;

   BlockingHelper bh(parent);

   int rc;
   while (true) {
      rc = libssh2_channel_exec(channel, command);
      //printd(5, "SSH2Channel::exec() cmd=%s rc=%d\n", command, rc);
      if (rc == LIBSSH2_ERROR_EAGAIN) {
	 if ((rc = parent->check_timeout(timeout_ms, "SSH2CHANNEL-EXEC-TIMEOUT", "SSH2CHANNEL-EXEC-ERROR", xsink)))
	    break;
	 continue;
      }
      if (rc)
	 parent->do_session_err_unlocked(xsink);
      break;
   }

   return rc;
}

#define QSSH2_BUFSIZE 4096

QoreStringNode *SSH2Channel::read(ExceptionSink *xsink, int stream_id, int timeout_ms) {
   AutoLocker al(parent->m);
   if (check_open(xsink))
      return 0;

   QoreStringNodeHolder str(new QoreStringNode(enc));

   BlockingHelper bh(parent);

   qore_offset_t rc;
   bool first = true;
   do {
     loop0:
      char buffer[QSSH2_BUFSIZE];
      rc = libssh2_channel_read_ex(channel, stream_id, buffer, QSSH2_BUFSIZE);

      //printd(5, "SSH2Channel::read() rc=%lld (EAGAIN=%d)\n", rc, LIBSSH2_ERROR_EAGAIN);
      if (rc > 0)
	 str->concat(buffer, rc);
      else if (rc == LIBSSH2_ERROR_EAGAIN && !str->strlen() && first) {
	 first = false;
	 if ((rc = parent->check_timeout(timeout_ms, "SSH2CHANNEL-READ-TIMEOUT", "SSH2CHANNEL-READ-ERROR", xsink)))
	    return 0;
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

QoreStringNode *SSH2Channel::read(qore_size_t size, int stream_id, int timeout_ms, ExceptionSink *xsink) {
   AutoLocker al(parent->m);
   if (check_open(xsink))
      return 0;

   QoreStringNodeHolder str(new QoreStringNode(enc));

   BlockingHelper bh(parent);

   qore_offset_t rc;
   // bytes read
   qore_size_t b_read = 0;
   // bytes remaining
   qore_size_t b_remaining = size;
   while (true) {
      char buffer[QSSH2_BUFSIZE];
      qore_size_t to_read = QSSH2_BUFSIZE < b_remaining ? QSSH2_BUFSIZE : b_remaining;
      rc = libssh2_channel_read_ex(channel, stream_id, buffer, to_read);

      //printd(5, "SSH2Channel::read() rc=%lld (EAGAIN=%d) b_read=%lld b_remaining=%lld to_read=%lld, size=%lld\n", rc, LIBSSH2_ERROR_EAGAIN, b_read, b_remaining, to_read, size);
      if (rc > 0) {
	 str->concat(buffer, rc);
	 b_read += rc;
	 b_remaining -= rc;
	 if (b_read >= size)
	    break;
	 continue;
      }

      if (!rc || rc == LIBSSH2_ERROR_EAGAIN) {
	 rc = parent->waitsocket_unlocked(timeout_ms);
	 if (!rc) {
	    xsink->raiseException("SSH2CHANNEL-READ-TIMEOUT", "read timeout after %dms reading %lld byte%s of %lld requested", timeout_ms, b_read, b_read == 1 ? "" : "s", size);
	    return 0;
	 }
	 if (rc < 0) {
	    xsink->raiseException("SSH2CHANNEL-READ-TIMEOUT", strerror(errno));
	    return 0;
	 }
      }
   }

   if (rc < 0 && rc != LIBSSH2_ERROR_EAGAIN) {
      parent->do_session_err_unlocked(xsink);
      return 0;
   }

   return str.release();
}

BinaryNode *SSH2Channel::readBinary(ExceptionSink *xsink, int stream_id, int timeout_ms) {
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
      rc = libssh2_channel_read_ex(channel, stream_id, buffer, QSSH2_BUFSIZE);

      //printd(5, "SSH2Channel::read() rc=%lld (EAGAIN=%d)\n", rc, LIBSSH2_ERROR_EAGAIN);
      if (rc > 0)
	 bin->append(buffer, rc);
      else if (rc == LIBSSH2_ERROR_EAGAIN && !bin->size() && first) {
	 first = false;
	 if ((rc = parent->check_timeout(timeout_ms, "SSH2CHANNEL-READBINARY-TIMEOUT", "SSH2CHANNEL-READBINARY-ERROR", xsink)))
	    return 0;
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

BinaryNode *SSH2Channel::readBinary(qore_size_t size, int stream_id, int timeout_ms, ExceptionSink *xsink) {
   AutoLocker al(parent->m);
   if (check_open(xsink))
      return 0;

   SimpleRefHolder<BinaryNode> bin(new BinaryNode);

   BlockingHelper bh(parent);

   qore_offset_t rc;
   // bytes read
   qore_size_t b_read = 0;
   // bytes remaining
   qore_size_t b_remaining = size;
   while (true) {
      char buffer[QSSH2_BUFSIZE];
      qore_size_t to_read = QSSH2_BUFSIZE < b_remaining ? QSSH2_BUFSIZE : b_remaining;
      rc = libssh2_channel_read_ex(channel, stream_id, buffer, to_read);

      //printd(5, "SSH2Channel::read() rc=%lld (EAGAIN=%d)\n", rc, LIBSSH2_ERROR_EAGAIN);
      if (rc > 0) {
	 bin->append(buffer, rc);
	 b_read += rc;
	 b_remaining -= rc;
	 if (b_read >= size)
	    break;
	 continue;
      }

      if (!rc || rc == LIBSSH2_ERROR_EAGAIN) {
	 rc = parent->waitsocket_unlocked(timeout_ms);
	 if (!rc) {
	    xsink->raiseException("SSH2CHANNEL-READBINARY-TIMEOUT", "read timeout after %dms reading %lld byte%s of %lld requested", timeout_ms, b_read, b_read == 1 ? "" : "s", size);
	    return 0;
	 }
	 if (rc < 0) {
	    xsink->raiseException("SSH2CHANNEL-READBINARY-TIMEOUT", strerror(errno));
	    return 0;
	 }
      }
   }

   if (rc < 0 && rc != LIBSSH2_ERROR_EAGAIN) {
      parent->do_session_err_unlocked(xsink);
      return 0;
   }

   return bin.release();
}

int SSH2Channel::write(ExceptionSink *xsink, const void *buf, qore_size_t buflen, int stream_id, int timeout_ms) {
   assert(buflen);

   AutoLocker al(parent->m);
   if (check_open(xsink))
      return -1;

   BlockingHelper bh(parent);
   
   qore_size_t b_sent = 0;
   while (true) {
      qore_offset_t rc;
      while (true) {
	 rc = libssh2_channel_write_ex(channel, stream_id, (char *)buf + b_sent, buflen - b_sent);
	 //printd(0, "SSH2Channel::write() buf=%p buflen=%lld stream_id=%d timeout_ms=%d rc=%lld b_sent=%lld\n", buf, buflen, stream_id, timeout_ms, rc, b_sent);

	 if (rc && rc != LIBSSH2_ERROR_EAGAIN)
	    break;

	 rc = parent->waitsocket_unlocked(timeout_ms);
	 if (!rc) {
	    xsink->raiseException("SSH2CHANNEL-WRITE-TIMEOUT", "write timeout after %dms writing %lld byte%s of %lld", timeout_ms, b_sent, b_sent == 1 ? "" : "s", buflen);
	    return -1;
	 }
	 if (rc < 0) {
	    xsink->raiseException("SSH2CHANNEL-WRITE-ERROR", strerror(errno));
	    return -1;
	 }
      }

      if (rc < 0)
	 parent->do_session_err_unlocked(xsink);

      b_sent += rc;
      if (b_sent >= buflen)
	 break;	 
   }

   return b_sent;
}

int SSH2Channel::close(ExceptionSink *xsink, int timeout_ms) {
   AutoLocker al(parent->m);
   if (check_open(xsink))
      return -1;

   BlockingHelper bh(parent);

   int rc;
   while (true) {
      rc = libssh2_channel_close(channel);
      if (rc == LIBSSH2_ERROR_EAGAIN) {
	 if ((rc = parent->check_timeout(timeout_ms, "SSH2CHANNEL-CLOSE-TIMEOUT", "SSH2CHANNEL-CLOSE-ERROR", xsink)))
	    break;
	 continue;
      }
      if (rc < 0)
	 parent->do_session_err_unlocked(xsink);
      break;
   }

   return rc;
}

int SSH2Channel::waitClosed(ExceptionSink *xsink, int timeout_ms) {
   AutoLocker al(parent->m);
   if (check_open(xsink))
      return -1;

   BlockingHelper bh(parent);

   int rc;
   while (true) {
      rc = libssh2_channel_wait_closed(channel);
      if (rc == LIBSSH2_ERROR_EAGAIN) {
	 if ((rc = parent->check_timeout(timeout_ms, "SSH2CHANNEL-WAITCLOSED-TIMEOUT", "SSH2CHANNEL-WAITCLOSED-ERROR", xsink)))
	    break;
	 continue;
      }
      if (rc < 0)
	 parent->do_session_err_unlocked(xsink);
      break;
   }

   return rc;
}

int SSH2Channel::getExitStatus(ExceptionSink *xsink) {
   AutoLocker al(parent->m);
   if (check_open(xsink))
      return -1;

   return libssh2_channel_get_exit_status(channel);
}

int SSH2Channel::requestX11Forwarding(ExceptionSink *xsink, int screen_number, bool single_connection, const char *auth_proto, const char *auth_cookie, int timeout_ms) {
   AutoLocker al(parent->m);
   if (check_open(xsink))
      return -1;

   BlockingHelper bh(parent);

   //printd(5, "SSH2Channel::requestX11Forwarding() screen_no=%d, single=%s, ap=%s, ac=%s\n", screen_number, single_connection ? "true" : "false", auth_proto ? auth_proto : "n/a", auth_cookie ? auth_cookie : "n/a");
   int rc; 
   while (true) {
      rc = libssh2_channel_x11_req_ex(channel, (int)single_connection, auth_proto, auth_cookie, screen_number);
      if (rc == LIBSSH2_ERROR_EAGAIN) {
	 if ((rc = parent->check_timeout(timeout_ms, "SSH2CHANNEL-REQUESTX11FORWARDING-TIMEOUT", "SSH2CHANNEL-REQUESTX11FORWARDING-ERROR", xsink)))
	    break;
	 continue;
      }
      if (rc < 0)
	 parent->do_session_err_unlocked(xsink);
      break;
   }
   return rc;
}

int SSH2Channel::extendedDataNormal(ExceptionSink *xsink, int timeout_ms) {
   AutoLocker al(parent->m);
   if (check_open(xsink))
      return -1;

   int rc;
   while (true) {
      rc = libssh2_channel_handle_extended_data2(channel, LIBSSH2_CHANNEL_EXTENDED_DATA_NORMAL); 
      if (rc == LIBSSH2_ERROR_EAGAIN) {
	 if ((rc = parent->check_timeout(timeout_ms, "SSH2CHANNEL-EXTENDEDDATANORMAL-TIMEOUT", "SSH2CHANNEL-EXTENDEDDATANORMAL-ERROR", xsink)))
	    break;
	 continue;
      }
      if (rc < 0)
	 parent->do_session_err_unlocked(xsink);
      break;
   }
   return rc;
}

int SSH2Channel::extendedDataMerge(ExceptionSink *xsink, int timeout_ms) {
   AutoLocker al(parent->m);
   if (check_open(xsink))
      return -1;

   int rc;
   while (true) {
      rc = libssh2_channel_handle_extended_data2(channel, LIBSSH2_CHANNEL_EXTENDED_DATA_MERGE); 
      if (rc == LIBSSH2_ERROR_EAGAIN) {
	 if ((rc = parent->check_timeout(timeout_ms, "SSH2CHANNEL-EXTENDEDDATAMERGE-TIMEOUT", "SSH2CHANNEL-EXTENDEDDATAMERGE-ERROR", xsink)))
	    break;
	 continue;
      }
      if (rc < 0)
	 parent->do_session_err_unlocked(xsink);
      break;
   }
   return rc;
}

int SSH2Channel::extendedDataIgnore(ExceptionSink *xsink, int timeout_ms) {
   AutoLocker al(parent->m);
   if (check_open(xsink))
      return -1;

   int rc;
   while (true) {
      rc = libssh2_channel_handle_extended_data2(channel, LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE); 
      if (rc == LIBSSH2_ERROR_EAGAIN) {
	 if ((rc = parent->check_timeout(timeout_ms, "SSH2CHANNEL-EXTENDEDDATAIGNORE-TIMEOUT", "SSH2CHANNEL-EXTENDEDDATAIGNORE-ERROR", xsink)))
	    break;
	 continue;
      }
      if (rc < 0)
	 parent->do_session_err_unlocked(xsink);
      break;
   }
   return rc;
}
