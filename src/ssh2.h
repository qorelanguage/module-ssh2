/*
  ssh2.h

  LibSSH2 integration to QORE

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

#ifndef QORE_SSH2_H

#define QORE_SSH2_H

#include <config.h>
#include <qore/Qore.h>

#include <libssh2.h>
#include <libssh2_sftp.h>

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
# ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif

#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <assert.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define DEFAULT_SSH_PORT 22

#ifndef DEFAULT_TIMEOUT_MS
// default 10 second I/O timeout
#define DEFAULT_TIMEOUT_MS 10000
#endif

// free a char* if it is not set to NULL, and set to NULL
static inline void free_string(char *&str) {
  if(str) {
    free(str);
  }
  str=(char*)NULL;
}

static inline int getMsTimeoutWithDefault(const AbstractQoreNode *a, int def) {
   if (is_nothing(a))
      return def;

   if (a->getType() == NT_DATE)
      return reinterpret_cast<const DateTimeNode *>(a)->getRelativeMilliseconds();

   return a->getAsInt();
}

// thread-local storage type for faked keyboard-interactive authentication
typedef QoreThreadLocalStorage<const char> TLKeyboardPassword;

// thread-local storage for faked keyboard-interactive authentication
extern TLKeyboardPassword keyboardPassword;

#endif

