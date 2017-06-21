/* -*- indent-tabs-mode: nil -*- */
/*
  SSH2Client.cpp

  libssh2 ssh2 client integration into qore

  Copyright 2009 Wolfgang Ritzinger
  Copyright (C) 2010 - 2014 Qore Technologies, sro

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
#include "SSH2Channel.h"

#include <memory>
#include <string>
#include <map>
#include <utility>
#include <sys/types.h>
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#include <errno.h>
#include <strings.h>
#include <sys/stat.h> 

#include <assert.h>
#include <unistd.h>

static const char *SSH2CLIENT_TIMEOUT = "SSH2CLIENT-TIMEOUT";
static const char *SSH2CLIENT_NOT_CONNECTED = "SSH2CLIENT-NOT-CONNECTED";
const char *SSH2_ERROR = "SSH2-ERROR";

std::string mode2str(const int mode) {
   std::string ret=std::string("----------");
   int tmode=mode;
   for(int i=2; i>=0; i--) {
      if (tmode & 001) {
         ret[1+2+i*3]='x';
      }
      if (tmode & 002) {
         ret[1+1+i*3]='w';
      }
      if (tmode & 004) {
         ret[1+0+i*3]='r';
      }
      tmode>>=3;
   }
#ifdef S_ISDIR
   if (S_ISDIR(mode)) {
      ret[0]='d';
   }
#endif
#ifdef S_ISBLK
   if (S_ISBLK(mode)) {
      ret[0]='b';
   }
#endif
#ifdef S_ISCHR
   if (S_ISCHR(mode)) {
      ret[0]='c';
   }
#endif
#ifdef S_ISFIFO
   if (S_ISFIFO(mode)) {
      ret[0]='p';
   }
#endif
#ifdef S_ISLNK
   if (S_ISLNK(mode)) {
      ret[0]='l';
   }
#endif
#ifdef S_ISSOCK
   if (S_ISSOCK(mode)) {
      ret[0]='s';
   }
#endif

   return ret;
}

static void map_ssh2_sbuf_to_hash(QoreHashNode *h, struct stat *sbuf) {
   // note that dev_t on Linux is an unsigned 64-bit integer, so we could lose precision here
   h->setKeyValue("mode",        new QoreBigIntNode(sbuf->st_mode), 0);
   h->setKeyValue("permissions", new QoreStringNode(mode2str(sbuf->st_mode)), 0);
   h->setKeyValue("size",        new QoreBigIntNode(sbuf->st_size), 0);
   
   h->setKeyValue("atime",       DateTimeNode::makeAbsolute(currentTZ(), (int64)sbuf->st_atime), 0);
   h->setKeyValue("mtime",       DateTimeNode::makeAbsolute(currentTZ(), (int64)sbuf->st_mtime), 0);
}

/**
 * SSH2Client constructor
 *
 * this just prefills the values for connection with hostname and port
 */
SSH2Client::SSH2Client(const char *hostname, const uint32_t port) : sshhost(hostname), sshport(port), sshauthenticatedwith(0), ssh_session(0) {
   setKeysIntern();
}

SSH2Client::SSH2Client(QoreURL &url, const uint32_t port) : 
   sshhost(url.getHost() ? url.getHost()->getBuffer() : ""), 
   sshuser(url.getUserName() ? url.getUserName()->getBuffer() : ""),
   sshpass(url.getPassword() ? url.getPassword()->getBuffer() : ""),
   sshport(port ? port : (uint32_t)url.getPort()),
   sshauthenticatedwith(0),
   ssh_session(0) {
   if (!sshport)
      sshport = DEFAULT_SSH_PORT;

   setKeysIntern();
}

/*
 * close session/connection
 * free resources
 */
SSH2Client::~SSH2Client() {
   QORE_TRACE("SSH2Client::~SSH2Client()");
   printd(5, "SSH2Client::~SSH2Client() this: %p\n", this);

   // first close all open channels
   {
      AutoLocker al(m);
      for (channel_set_t::iterator i = channel_set.begin(), e = channel_set.end(); i != e; ++i) {
	 (*i)->close_unlocked();
      }
   }
   
   // disconnect
   ssh_disconnect_unlocked(true);
}

void SSH2Client::setKeysIntern() {
#ifdef HAVE_PWD_H
   // only set if the current user has access to the filesystem
   if (getProgram()->getParseOptions64() & PO_NO_FILESYSTEM)
      return;

   // prefill the user and 'estimate' the key files for rsa
   struct passwd *usrpwd = getpwuid(getuid());
   if (usrpwd) {
      sshuser = usrpwd->pw_name;
      sshkeys_priv = usrpwd->pw_dir;
      sshkeys_priv += "/.ssh/id_rsa";
#ifdef _QORE_HAS_PATH_IS_READABLE
      if (!q_path_is_readable(sshkeys_priv.c_str())) {
         printd(5, "SSH2Client::setKeysIntern() skipping automatic setting of keys because '%s' is not readable\n", sshkeys_priv.c_str());
         sshkeys_priv.clear();
         return;
      }
#endif
      sshkeys_pub = usrpwd->pw_dir;
      sshkeys_pub += "/.ssh/id_rsa.pub";
#ifdef _QORE_HAS_PATH_IS_READABLE
      if (!q_path_is_readable(sshkeys_pub.c_str())) {
         printd(5, "SSH2Client::setKeysIntern() skipping automatic setting of keys because '%s' is not readable\n", sshkeys_pub.c_str());
         sshkeys_priv.clear();
         sshkeys_pub.clear();
         return;
      }
#endif
   }
#endif    
}

/**
 * disconnect from the server if connected
 *
 * if force is not 0 then there will be no exception written.
 *
 * return 0 on ok.
 * sets errno
 */
int SSH2Client::ssh_disconnect_unlocked(bool force, int timeout_ms, ExceptionSink *xsink) {
   if (!ssh_session) {
      if (!force) {
         errno = EINVAL;
         xsink && xsink->raiseException(SSH2CLIENT_NOT_CONNECTED, "disconnect(): %s", strerror(errno));
      }
   }
   else {
      set_blocking_unlocked(false);

      // close ssh session if not null
      int rc;
      while ((rc = libssh2_session_disconnect(ssh_session, (char*)"qore program disconnect")) == LIBSSH2_ERROR_EAGAIN) {
         if (waitsocket_unlocked(xsink, SSH2CLIENT_TIMEOUT, "SSSHCLIENT-DISCONNECT", "SSHClient::disconnect", timeout_ms))
            break;
      }

      while ((rc = libssh2_session_free(ssh_session)) == LIBSSH2_ERROR_EAGAIN) {
         // there can be a memory leak here, but there is no other way to free memory without waiting for the remote socket
         if (waitsocket_unlocked(xsink, SSH2CLIENT_TIMEOUT, "SSSHCLIENT-DISCONNECT", "SSHClient::disconnect", timeout_ms))
            break;
      }

      ssh_session = 0;
   }

   if (sshauthenticatedwith)
      sshauthenticatedwith = 0;

   socket.close();
   return 0;
}

int SSH2Client::ssh_disconnect(bool force, int timeout_ms, ExceptionSink *xsink) {
   AutoLocker al(m);

   return ssh_disconnect_unlocked(force, timeout_ms, xsink);
}

/**
 * return 1 if we think we are connected
 */
int SSH2Client::ssh_connected_unlocked() {
   return (ssh_session? 1: 0);
}

int SSH2Client::ssh_connected() {
   AutoLocker al(m);

   return ssh_connected_unlocked();
}

QoreObject *SSH2Client::register_channel_unlocked(LIBSSH2_CHANNEL *channel) {
   SSH2Channel *chan = new SSH2Channel(channel, this);
   channel_set.insert(chan);
   return new QoreObject(QC_SSH2CHANNEL, getProgram(), chan);
}

const char *SSH2Client::getHost() {
   return sshhost.c_str();
}

const uint32_t SSH2Client::getPort() {
   return sshport;
}

const char *SSH2Client::getAuthenticatedWith() {
   return sshauthenticatedwith;
}

void SSH2Client::deref(ExceptionSink *xsink) {
   if (ROdereference()) {
#ifdef _QORE_HAS_SOCKET_PERF_API
      // this function is only exported in versions of qore with the socket performance API
      // and must be called before the QoreSocket object is destroyed
      socket.cleanup(xsink);
#endif
      delete this;
   }
}

int SSH2Client::setUser(const char *user) {
   AutoLocker al(m);

   if (ssh_connected_unlocked())
      return -1;

   sshuser = user;
   return 0;
}

const char *SSH2Client::getUser() {
   return sshuser.c_str();
}

int SSH2Client::setPassword(const char *pwd) {
   AutoLocker al(m);

   if (ssh_connected_unlocked())
      return -1;

   sshpass = pwd;
   return 0;
}

const char *SSH2Client::getPassword() {
   return sshpass.c_str();
}

int SSH2Client::setKeys(const char *priv, const char *pub, ExceptionSink* xsink) {
   AutoLocker al(m);

   if (ssh_connected_unlocked()) {
      xsink->raiseException(SSH2_CONNECTED, "usage of SSH2Base::setKeys() is not allowed when connected");
      return -1;
   }

   sshkeys_priv.clear();
   sshkeys_pub.clear();

   // if the strings are null then ignore
   if (priv && strlen(priv)) {
      sshkeys_priv = priv;
#ifdef _QORE_HAS_PATH_IS_READABLE
      if (!q_path_is_readable(sshkeys_priv.c_str())) {
         xsink->raiseException("SSH2-SETKEYS-ERROR", "private key '%s' is not readable", sshkeys_priv.c_str());
         sshkeys_priv.clear();
         return -1;
      }
#endif

      if (pub)
         sshkeys_pub = pub;
      else {
         sshkeys_pub = priv;
         sshkeys_pub += ".pub";
      }

#ifdef _QORE_HAS_PATH_IS_READABLE
      if (!q_path_is_readable(sshkeys_pub.c_str())) {
         xsink->raiseException("SSH2-SETKEYS-ERROR", "public key '%s' is not readable", sshkeys_pub.c_str());
         sshkeys_priv.clear();
         sshkeys_pub.clear();
         return -1;
      }
#endif

   }
   return 0;
}

const char *SSH2Client::getKeyPriv() {
   return sshkeys_priv.c_str();
}

const char *SSH2Client::getKeyPub() {
   return sshkeys_pub.c_str();
}

QoreStringNode *SSH2Client::fingerprint_unlocked() {
   if (!ssh_connected_unlocked())
      return 0;

   const char *fingerprint = libssh2_hostkey_hash(ssh_session, LIBSSH2_HOSTKEY_HASH_MD5);
  
   if (!fingerprint)
      return 0;

   QoreStringNode *fpstr = new QoreStringNode;
   fpstr->sprintf("%02X", (unsigned char)fingerprint[0]);
   for (int i = 1; i < 16; i++)
      fpstr->sprintf(":%02X", (unsigned char)fingerprint[i]);
   return fpstr;
}

/**
 * return the fingerprint given from the server as md5 string
 */
QoreStringNode *SSH2Client::fingerprint() {
   AutoLocker al(m);

   return fingerprint_unlocked();
}

static void kbd_callback(const char *name, int name_len,
			 const char *instruction, int instruction_len, int num_prompts,
			 const LIBSSH2_USERAUTH_KBDINT_PROMPT *prompts,
			 LIBSSH2_USERAUTH_KBDINT_RESPONSE *responses,
			 void **abstract) {
   const char *password = keyboardPassword.get();
   //printd(5, "kdb_callback() num_prompts=%d pass=%s\n", num_prompts, password);
   if (num_prompts == 1) {
      responses[0].text = strdup(password);
      responses[0].length = strlen(password);
   }
} /* kbd_callback */ 

int SSH2Client::startup_unlocked() {
#ifdef HAVE_LIBSSH2_SESSION_HANDSHAKE
   return libssh2_session_handshake(ssh_session, socket.getSocket());
#else
   return libssh2_session_startup(ssh_session, socket.getSocket());
#endif
}

/**
 * connect()
 * returns:
 * 0	ok
 * 1	host not found
 * 2	port not identified
 * 3	socket not created
 * 4	session init failure
 */
int SSH2Client::ssh_connect_unlocked(int timeout_ms, ExceptionSink *xsink = 0) {
   // check for host connectivity
   // getaddrinfo(3)
   // see Socket class
   // create socket
   // init session
   // set to blocking
   // startup session with socket

   static const char *SSH2CLIENT_CONNECT_ERROR = "SSH2CLIENT-CONNECT-ERROR";

   QORE_TRACE("SSH2Client::connect()");

   printd(1, "SSH2Client::connect(%s:%d, %dms)\n", sshhost.c_str(), sshport, timeout_ms);
  
   // sanity check of data
   if (sshuser.empty()) {
      xsink && xsink->raiseException(SSH2CLIENT_CONNECT_ERROR, "ssh user must not be NOTHING");
      return -1;
   }

   int auth_pw = 0;
   char *userauthlist;
   int rc;

   bool loggedin = false; // tells us if we are logged in (or at least think so)

   // force disconnect session if already connected
   if (ssh_session)
      ssh_disconnect_unlocked(true);
  
   if (socket.connectINET(sshhost.c_str(), sshport, timeout_ms, xsink))
      return -1;
  
   // Create a session instance
   ssh_session = libssh2_session_init();
   if (!ssh_session) {
      ssh_disconnect_unlocked(true); // clean up connection
      xsink && xsink->raiseException(SSH2_ERROR, "error in libssh2_session_init(): ", strerror(errno));
      return -1;
   }

   // make sure the connection is made with non-blocking I/O
   set_blocking_unlocked(false);

   // ... start it up. This will trade welcome banners, exchange keys,
   // and setup crypto, compression, and MAC layers
   while ((rc = startup_unlocked()) == LIBSSH2_ERROR_EAGAIN) {
      if (waitsocket_unlocked(xsink, SSH2CLIENT_TIMEOUT, SSH2_ERROR, "SSH2Client::connect", timeout_ms)) {
         ssh_disconnect_unlocked(true); // clean up connection
         return -1;
      }
   }

   if (rc) {
      ssh_disconnect_unlocked(true); // clean up connection
      xsink && xsink->raiseException(SSH2_ERROR, "failure establishing SSH session: %d", rc);
      return -1;
   }

   // check what types are available for authentifcation
   while (true) {
      userauthlist = libssh2_userauth_list(ssh_session, sshuser.c_str(), sshuser.size());
      if (!userauthlist && libssh2_session_last_errno(ssh_session) == LIBSSH2_ERROR_EAGAIN) {
         if (waitsocket_unlocked(xsink, SSH2CLIENT_TIMEOUT, SSH2_ERROR, "SSH2Client::connect", timeout_ms)) {
            ssh_disconnect_unlocked(true); // clean up connection
            return -1;
         }
         continue;
      }
      break;         
   }

   assert(!sshauthenticatedwith);

   printd(5, "userauthlist: %s\n", userauthlist ? userauthlist : "n/a");

   // set flags for use with authentification
   if (userauthlist) {
      if (strstr(userauthlist, "publickey"))
         auth_pw |= QAUTH_PUBLICKEY;
      if (strstr(userauthlist, "password"))
         auth_pw |= QAUTH_PASSWORD;
      if (strstr(userauthlist, "keyboard-interactive"))
         auth_pw |= QAUTH_KEYBOARD_INTERACTIVE;
   }
      
   // try auth 
   // try publickey if available
   if (!loggedin && (auth_pw & QAUTH_PUBLICKEY) && (!sshkeys_priv.empty() && !sshkeys_pub.empty())) {
      printd(5, "SSH2Client::connect(): try pubkey auth: %s %s\n", sshkeys_priv.c_str(), sshkeys_pub.c_str());
      while ((rc = libssh2_userauth_publickey_fromfile(ssh_session, sshuser.c_str(), sshkeys_pub.c_str(), sshkeys_priv.c_str(), sshpass.c_str())) == LIBSSH2_ERROR_EAGAIN) {
         if (waitsocket_unlocked(xsink, SSH2CLIENT_TIMEOUT, SSH2_ERROR, "SSH2Client::connect", timeout_ms)) {
            ssh_disconnect_unlocked(true); // clean up connection
            return -1;
         }
      }
      if (!rc) {
         loggedin = true;
         sshauthenticatedwith = "publickey";
         printd(5, "publickey authentication succeeded\n");
      }
#ifdef DEBUG
      else
         printd(5, "publickey authentication failed\n");
#endif	
   }
   
   // try password and keyboard-interactive first if a password was given
   if (!loggedin && (auth_pw & QAUTH_PASSWORD)) {
      printd(5, "SSH2Client::connect(): try user/pass auth: %s/%s\n", sshuser.c_str(), sshpass.c_str());
      while ((rc = libssh2_userauth_password(ssh_session, sshuser.c_str(), sshpass.c_str())) == LIBSSH2_ERROR_EAGAIN) {
         if (waitsocket_unlocked(xsink, SSH2CLIENT_TIMEOUT, SSH2_ERROR, "SSH2Client::connect", timeout_ms)) {
            ssh_disconnect_unlocked(true); // clean up connection
            return -1;
         }
      }
      if (!rc) {
         loggedin = true;
         sshauthenticatedwith = "password";
         printd(5, "password authentication succeeded\n");
      }
#ifdef DEBUG
      else
         printd(5, "password authentication failed\n");
#endif
   }
   
   if (!loggedin && (auth_pw & QAUTH_KEYBOARD_INTERACTIVE)) {
      printd(5, "SSH2Client::connect(): try user/pass with keyboard-interactive auth: %s/%s\n", sshuser.c_str(), sshpass.c_str());
      // thread thread-local storage for password for fake keyboard-interactive authentication
      keyboardPassword.set(sshpass.c_str());
      while ((rc = libssh2_userauth_keyboard_interactive(ssh_session, sshuser.c_str(), &kbd_callback)) == LIBSSH2_ERROR_EAGAIN) {
         if (waitsocket_unlocked(xsink, SSH2CLIENT_TIMEOUT, SSH2_ERROR, "SSH2Client::connect", timeout_ms)) {
            ssh_disconnect_unlocked(true); // clean up connection
            return -1;
         }
      }
      if (!rc) {
         loggedin = true;
         sshauthenticatedwith = "keyboard-interactive";
         printd(5, "keyboard-interactive authentication succeeded\n");
      }
#ifdef DEBUG
      else
         printd(5, "keyboard-interactive authentication failed\n");
#endif
   }
  
   // could we auth?
   if (!loggedin) {
      ssh_disconnect_unlocked(true); // clean up connection
      xsink && xsink->raiseException("SSH2CLIENT-AUTH-ERROR", "No proper authentication method found");
      return -1;
   }

   set_blocking_unlocked(true);

#ifdef HAVE_LIBSSH2_KEEPALIVE_CONFIG
   // set keepalive
   libssh2_keepalive_config(ssh_session, 1, QKEEPALIVE_DEFAULT);
#endif

   return 0;
}

int SSH2Client::ssh_connect(int timeout_ms, ExceptionSink *xsink = 0) {
   AutoLocker al(m);

   return ssh_connect_unlocked(timeout_ms, xsink);
}

QoreHashNode *SSH2Client::ssh_info() {
   AutoLocker al(m);

   return ssh_info_intern();
}

QoreHashNode *SSH2Client::ssh_info_intern() {
   QoreHashNode *ret = new QoreHashNode;
   ret->setKeyValue("ssh2host", new QoreStringNode(getHost()), 0);
   ret->setKeyValue("ssh2port", new QoreBigIntNode(getPort()), 0);
   ret->setKeyValue("ssh2user", new QoreStringNode(getUser()), 0);
   //ret->setKeyValue("ssh2pass", new QoreStringNode(myself->sshpass), 0);
   ret->setKeyValue("keyfile_priv", new QoreStringNode(getKeyPriv()), 0);
   ret->setKeyValue("keyfile_pub", new QoreStringNode(getKeyPub()), 0);
   ret->setKeyValue("fingerprint", fingerprint_unlocked(), 0);
   //  ret->setKeyValue("userauthlist", myself->sshauthlist? new QoreStringNode(myself->sshauthlist): NULL, 0);
   const char *str=getAuthenticatedWith();
   ret->setKeyValue("authenticated", str ? new QoreStringNode(str) : NULL, 0);
   ret->setKeyValue("connected", get_bool_node(ssh_connected_unlocked()), 0);
   
   if (ssh_connected_unlocked()) {
      const char *meth;
      QoreHashNode *methods = new QoreHashNode;
#ifdef LIBSSH2_METHOD_KEX
      meth = libssh2_session_methods(ssh_session, LIBSSH2_METHOD_KEX);
      if (meth)
         methods->setKeyValue("KEX", new QoreStringNode(meth), 0);
#endif
#ifdef LIBSSH2_METHOD_HOSTKEY
      meth = libssh2_session_methods(ssh_session, LIBSSH2_METHOD_HOSTKEY);
      if (meth)
         methods->setKeyValue("HOSTKEY", new QoreStringNode(meth), 0);
#endif
#ifdef LIBSSH2_METHOD_CRYPT_CS
      meth = libssh2_session_methods(ssh_session, LIBSSH2_METHOD_CRYPT_CS);
      if (meth)
         methods->setKeyValue("CRYPT_CS", new QoreStringNode(meth), 0);
#endif
#ifdef LIBSSH2_METHOD_CRYPT_SC
      meth = libssh2_session_methods(ssh_session, LIBSSH2_METHOD_CRYPT_SC);
      if (meth)
         methods->setKeyValue("CRYPT_SC", new QoreStringNode(meth), 0);
#endif
#ifdef LIBSSH2_METHOD_MAC_CS
      meth = libssh2_session_methods(ssh_session, LIBSSH2_METHOD_MAC_CS);
      if (meth)
         methods->setKeyValue("MAC_CS", new QoreStringNode(meth), 0);
#endif
#ifdef LIBSSH2_METHOD_MAC_SC
      meth = libssh2_session_methods(ssh_session, LIBSSH2_METHOD_MAC_SC);
      if (meth)
         methods->setKeyValue("MAC_SC", new QoreStringNode(meth), 0);
#endif
#ifdef LIBSSH2_METHOD_COMP_CS
      meth = libssh2_session_methods(ssh_session, LIBSSH2_METHOD_COMP_CS);
      if (meth)
         methods->setKeyValue("COMP_CS", new QoreStringNode(meth), 0);
#endif
#ifdef LIBSSH2_METHOD_COMP_SC
      meth = libssh2_session_methods(ssh_session, LIBSSH2_METHOD_COMP_SC);
      if (meth)
         methods->setKeyValue("COMP_SC", new QoreStringNode(meth), 0);
#endif
#ifdef LIBSSH2_METHOD_LANG_CS
      meth = libssh2_session_methods(ssh_session, LIBSSH2_METHOD_LANG_CS);
      if (meth)
         methods->setKeyValue("LANG_CS", new QoreStringNode(meth), 0);
#endif
#ifdef LIBSSH2_METHOD_LANG_SC
      meth = libssh2_session_methods(ssh_session, LIBSSH2_METHOD_LANG_SC);
      if (meth)
         methods->setKeyValue("LANG_SC", new QoreStringNode(meth), 0);
#endif
      ret->setKeyValue("methods", methods, 0);
   }

   return ret;
}

QoreObject *SSH2Client::openSessionChannel(ExceptionSink *xsink, int timeout_ms) {
   static const char *SSH2CLIENT_OPENSESSIONCHANNEL_ERROR = "SSH2CLIENT-OPENSESSIONCHANNEL-ERROR";

   AutoLocker al(m);
   
   if (!ssh_connected_unlocked()) {
      xsink->raiseException(SSH2CLIENT_NOT_CONNECTED, "cannot call SSH2Client::openSessionChannel() while client is not connected");
      return 0;
   }

   BlockingHelper bh(this);

   LIBSSH2_CHANNEL *channel;
   while (true) {
      channel = libssh2_channel_open_session(ssh_session);
      //printd(0, "SSH2Client::openSessionChannel(timeout_ms = %d) channel=%p rc=%d\n", timeout_ms, channel, libssh2_session_last_errno(ssh_session));
      if (!channel) {
	 if (libssh2_session_last_error(ssh_session, 0, 0, 0) == LIBSSH2_ERROR_EAGAIN) {
	    if (waitsocket_unlocked(xsink, SSH2CLIENT_TIMEOUT, SSH2CLIENT_OPENSESSIONCHANNEL_ERROR, "SSH2Client::openSessionChannel", timeout_ms))
	       return 0;
	    continue;
	 }
	 do_session_err_unlocked(xsink);
	 return 0;
      }
      break;
   }
   
   return register_channel_unlocked(channel);
}

QoreObject *SSH2Client::openDirectTcpipChannel(ExceptionSink *xsink, const char *host, int port, const char *shost, int sport, int timeout_ms) {
   static const char *SSH2CLIENT_OPENDIRECTTCPIPCHANNEL_ERROR = "SSH2CLIENT-OPENDIRECTTCPIPCHANNEL-ERROR";

   AutoLocker al(m);
   
   if (!ssh_connected_unlocked()) {
      xsink->raiseException(SSH2CLIENT_NOT_CONNECTED, "cannot call SSH2Client::openDirectTcpipChannel() while client is not connected");
      return 0;
   }
   
   BlockingHelper bh(this);

   LIBSSH2_CHANNEL *channel;
   while (true) {
      channel = libssh2_channel_direct_tcpip_ex(ssh_session, host, port, shost, sport);
      if (!channel) {
	 if (libssh2_session_last_error(ssh_session, 0, 0, 0) == LIBSSH2_ERROR_EAGAIN) {
	    if (waitsocket_unlocked(xsink, SSH2CLIENT_TIMEOUT, SSH2CLIENT_OPENDIRECTTCPIPCHANNEL_ERROR, "SSH2Client::openDirectTcpipChannel", timeout_ms))
	       return 0;
	    continue;
	 }
	 do_session_err_unlocked(xsink);
	 return 0;
      }
      break;
   }

   return register_channel_unlocked(channel);
}

QoreObject *SSH2Client::scpGet(ExceptionSink *xsink, const char *path, int timeout_ms, QoreHashNode *statinfo) {
   static const char *SSH2CLIENT_SCPGET_ERROR = "SSH2CLIENT-SCPGET-ERROR";

   AutoLocker al(m);
   
   if (!ssh_connected_unlocked()) {
      xsink->raiseException(SSH2CLIENT_NOT_CONNECTED, "cannot call SSH2Client::scpGet() while client is not connected");
      return 0;
   }
   
   BlockingHelper bh(this);

   struct stat sb;
   LIBSSH2_CHANNEL *channel;
   while (true) {
      channel = libssh2_scp_recv(ssh_session, path, &sb);
      if (!channel) {
	 if (libssh2_session_last_error(ssh_session, 0, 0, 0) == LIBSSH2_ERROR_EAGAIN) {
	    if (waitsocket_unlocked(xsink, SSH2CLIENT_TIMEOUT, SSH2CLIENT_SCPGET_ERROR, "SSH2Client::scpGet", timeout_ms))
	       return 0;
	    continue;
	 }
	 do_session_err_unlocked(xsink);
	 return 0;
      }
      break;
   }

   // write file status info to statinfo if available
   if (statinfo)
      map_ssh2_sbuf_to_hash(statinfo, &sb);

   return register_channel_unlocked(channel);   
}

QoreObject *SSH2Client::scpPut(ExceptionSink *xsink, const char *path, size_t size, int mode, long mtime, long atime, int timeout_ms) {
   static const char *SSH2CLIENT_SCPPUT_ERROR = "SSH2CLIENT-SCPPUT-ERROR";

   AutoLocker al(m);
   
   if (!ssh_connected_unlocked()) {
      xsink->raiseException(SSH2CLIENT_NOT_CONNECTED, "cannot call SSH2Client::scpPut() while client is not connected");
      return 0;
   }

   BlockingHelper bh(this);
   
   LIBSSH2_CHANNEL *channel;
   while (true) {
      channel = libssh2_scp_send_ex(ssh_session, path, mode, size, mtime, atime);
      if (!channel) {
	 if (libssh2_session_last_error(ssh_session, 0, 0, 0) == LIBSSH2_ERROR_EAGAIN) {
	    if (waitsocket_unlocked(xsink, SSH2CLIENT_TIMEOUT, SSH2CLIENT_SCPPUT_ERROR, "SSH2Client::scpPut", timeout_ms))
	       return 0;
	    continue;
	 }
	 do_session_err_unlocked(xsink);
	 return 0;
      }
      break;
   }

   return register_channel_unlocked(channel);   
}

#ifdef _QORE_HAS_SOCKET_PERF_API
void SSH2Client::clearWarningQueue(ExceptionSink* xsink) {
   AutoLocker al(m);
   socket.clearWarningQueue(xsink);
}

void SSH2Client::setWarningQueue(ExceptionSink* xsink, int64 warning_ms, int64 warning_bs, Queue* wq, AbstractQoreNode* arg, int64 min_ms) {
   AutoLocker al(m);
   socket.setWarningQueue(xsink, warning_ms, warning_bs, wq, arg, min_ms);
}

QoreHashNode* SSH2Client::getUsageInfo() const {
   AutoLocker al(m);
   return socket.getUsageInfo();
}

void SSH2Client::clearStats() {
   AutoLocker al(m);
   socket.clearStats();
}
#endif
