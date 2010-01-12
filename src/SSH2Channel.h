/*
  SSH2Channel.h

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

#ifndef _QORE_SSH2CHANNEL_H

#define _QORE_SSH2CHANNEL_H

#include "ssh2.h"

#include <qore/Qore.h>

DLLLOCAL extern qore_classid_t CID_SSH2_CHANNEL;
DLLLOCAL extern QoreClass *QC_SSH2CHANNEL;

DLLLOCAL QoreClass *initSSH2ChannelClass();

class SSH2Client;

class SSH2Channel : public AbstractPrivateData {
   friend class SSH2Client;

protected:
   LIBSSH2_CHANNEL *channel;
   SSH2Client *parent;

   void close_unlocked() {
      libssh2_channel_free(channel);
      channel = 0;
   }

   int check_open(ExceptionSink *xsink) {
      if (channel)
	 return 0;

      xsink->raiseException("SSH2-CHANNEL-ERROR", "The SSH2 channel has already been closed");
      return -1;
   }

public:
   // channel is already registered with parent when it's created
   DLLLOCAL SSH2Channel(LIBSSH2_CHANNEL *n_channel, SSH2Client *n_parent) : channel(n_channel), parent(n_parent) {
   }
   DLLLOCAL ~SSH2Channel() {
      // channel must be closed before object is destroyed
      assert(!channel);
   }
   DLLLOCAL void destructor();
   DLLLOCAL int setenv(const char *name, const char *value, ExceptionSink *xsink);
   DLLLOCAL int requestPty(ExceptionSink *xsink, const QoreString *term = 0, const QoreString *modes = 0, int width = LIBSSH2_TERM_WIDTH, 
			   int height = LIBSSH2_TERM_HEIGHT, int width_px = LIBSSH2_TERM_WIDTH_PX, 
			   int height_px = LIBSSH2_TERM_HEIGHT_PX);
   DLLLOCAL int shell(ExceptionSink *xsink);
   DLLLOCAL bool eof(ExceptionSink *xsink);
   DLLLOCAL int exec(const char *command, ExceptionSink *xsink);
   DLLLOCAL QoreStringNode *read(ExceptionSink *xsink);
   DLLLOCAL int write(ExceptionSink *xsink, const void *buf, qore_size_t buflen, int stream_id = 0);
};

#endif _QORE_SSH2CHANNEL_H
