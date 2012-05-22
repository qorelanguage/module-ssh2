/* -*- indent-tabs-mode: nil -*- */
/*
  SSH2Client.cc

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
      if(tmode & 001) {
         ret[1+2+i*3]='x';
      }
      if(tmode & 002) {
         ret[1+1+i*3]='w';
      }
      if(tmode & 004) {
         ret[1+0+i*3]='r';
      }
      tmode>>=3;
   }
#ifdef S_ISDIR
   if(S_ISDIR(mode)) {
      ret[0]='d';
   }
#endif
#ifdef S_ISBLK
   if(S_ISBLK(mode)) {
      ret[0]='b';
   }
#endif
#ifdef S_ISCHR
   if(S_ISCHR(mode)) {
      ret[0]='c';
   }
#endif
#ifdef S_ISFIFO
   if(S_ISFIFO(mode)) {
      ret[0]='p';
   }
#endif
#ifdef S_ISLNK
   if(S_ISLNK(mode)) {
      ret[0]='l';
   }
#endif
#ifdef S_ISSOCK
   if(S_ISSOCK(mode)) {
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
SSH2Client::SSH2Client(const char *hostname, const uint32_t port) {
   // remember host settings
   sshhost=strdup(hostname);
   sshport=port;
   sshuser=(char *)NULL;
   sshpass=(char *)NULL;
   sshkeys_pub=(char *)NULL;
   sshkeys_priv=(char *)NULL;
   sshauthenticatedwith=NULL; // will be filled on connect

#ifdef HAVE_PWD_H
   // prefill the user and 'estimate' the key files for rsa
   struct passwd *usrpwd = getpwuid(getuid());
   if(usrpwd!=NULL) {
      char thome[PATH_MAX];
      sshuser=strdup(usrpwd->pw_name);
      strncpy(thome, usrpwd->pw_dir, sizeof(thome)-1);
      sshkeys_pub=strdup(strncat(thome, "/.ssh/id_rsa.pub", sizeof(thome)-1));
      strncpy(thome, usrpwd->pw_dir, sizeof(thome)-1);
      sshkeys_priv=strdup(strncat(thome, "/.ssh/id_rsa", sizeof(thome)-1));
   }
#endif
    
   ssh_session=NULL;
}

SSH2Client::SSH2Client(QoreURL &url, const uint32_t port) {
   // remember host settings
   sshhost = url.take_host();
   sshport = port ? port : url.getPort();
   if (!sshport)
      sshport = DEFAULT_SSH_PORT;
   sshuser = url.take_username();
   sshpass = url.take_password();
   sshkeys_pub = 0;
   sshkeys_priv = 0;
   sshauthenticatedwith = 0; // will be filled on connect

#ifdef HAVE_PWD_H
   // prefill the user if not already set and 'estimate' the key files for rsa
   struct passwd *usrpwd = getpwuid(getuid());
   if (usrpwd) {
      char thome[PATH_MAX];
      if (!sshuser)
         sshuser = strdup(usrpwd->pw_name);
      strncpy(thome, usrpwd->pw_dir, sizeof(thome) - 1);
      sshkeys_pub = strdup(strncat(thome, "/.ssh/id_rsa.pub", sizeof(thome) - 1));
      strncpy(thome, usrpwd->pw_dir, sizeof(thome) - 1);
      sshkeys_priv = strdup(strncat(thome, "/.ssh/id_rsa", sizeof(thome) - 1));

      //printd(5, "keys='%s' priv='%s'\n", sshkeys_pub, sshkeys_priv);
   }
#endif
    
   ssh_session = 0;
}

/*
 * close session/connection
 * free ressources
 */
SSH2Client::~SSH2Client() {
   QORE_TRACE("SSH2Client::~SSH2Client()");
   printd(5, "SSH2Client::~SSH2Client() this=%08p\n", this);

   // first close all open channels
   {
      AutoLocker al(m);
      for (channel_set_t::iterator i = channel_set.begin(), e = channel_set.end(); i != e; ++i) {
	 (*i)->close_unlocked();
      }
   }
   
   // close up
   
   // disconnect
   ssh_disconnect_unlocked(true);
   
   // free
   free_string(sshhost);
   free_string(sshuser);
   free_string(sshpass);
   free_string(sshkeys_pub);
   free_string(sshkeys_priv);
   
   sshauthenticatedwith = 0;
}

/**
 * disconnect from the server if connected
 *
 * if force is not 0 then there will be no exception written.
 *
 * return 0 on ok.
 * sets errno
 */
int SSH2Client::ssh_disconnect_unlocked(bool force, ExceptionSink *xsink) {
   if (!ssh_session && !force) {
      errno = EINVAL;
      xsink && xsink->raiseException(SSH2CLIENT_NOT_CONNECTED, "disconnect(): %s", strerror(errno));
   }

   if (ssh_session) {
      // close ssh session if not null
      libssh2_session_disconnect(ssh_session, (char*)"qore program disconnect");
      libssh2_session_free(ssh_session);
      ssh_session = NULL;
   }

   socket.close();

   return 0;
}

int SSH2Client::ssh_disconnect(bool force, ExceptionSink *xsink) {
   AutoLocker al(m);

   return ssh_disconnect_unlocked(force, xsink);
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
   return sshhost;
}

const uint32_t SSH2Client::getPort() {
   return sshport;
}

const char *SSH2Client::getAuthenticatedWith() {
   return sshauthenticatedwith;
}

void SSH2Client::deref(ExceptionSink *xsink) {
   if(ROdereference()) {
      delete this;
   }
}

int SSH2Client::setUser(const char *user) {
   AutoLocker al(m);

   if (ssh_connected_unlocked())
      return -1;

   free_string(sshuser);
   sshuser=strdup(user);
   return 0;
}

const char *SSH2Client::getUser() {
   return sshuser;
}

int SSH2Client::setPassword(const char *pwd) {
   AutoLocker al(m);

   if (ssh_connected_unlocked())
      return -1;

   free_string(sshpass);
   sshpass=strdup(pwd);
   return 0;
}

const char *SSH2Client::getPassword() {
   return sshpass;
}

int SSH2Client::setKeys(const char *priv, const char *pub) {
   AutoLocker al(m);

   if (ssh_connected_unlocked())
      return -1;

   free_string(sshkeys_priv);
   free_string(sshkeys_pub);

   // if the strings are null then ignore
   if(priv) {
      sshkeys_priv=strdup(priv);
      if(pub) {
         sshkeys_pub=strdup(pub);
      }
      else if(strlen(priv)) {
         std::string str=std::string(priv) + std::string(".pub");
         sshkeys_pub=strdup(str.c_str());
      }
   }
   return 0;
}

const char *SSH2Client::getKeyPriv() {
   return sshkeys_priv;
}

const char *SSH2Client::getKeyPub() {
   return sshkeys_pub;
}

QoreStringNode *SSH2Client::fingerprint_unlocked() {
   if (!ssh_connected_unlocked()) {
      return NULL;
   }

   const char *fingerprint = libssh2_hostkey_hash(ssh_session, LIBSSH2_HOSTKEY_HASH_MD5);
  
   if(!fingerprint) {
      return NULL;
   }

   QoreStringNode *fpstr=new QoreStringNode();
   fpstr->sprintf("%02X", (unsigned char)fingerprint[0]);
   for(int i=1; i<16; i++) {
      fpstr->sprintf(":%02X", (unsigned char)fingerprint[i]);
   }
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

   printd(1, "SSH2Client::connect(%s:%d, %dms)\n", sshhost, sshport, timeout_ms);
  
   // sanity check of data
   if (!sshuser) {
      xsink && xsink->raiseException(SSH2CLIENT_CONNECT_ERROR, "ssh user must not be NOTHING");
      return -1;
   }

   int auth_pw = 0;
   char *userauthlist;
   int rc;

   int loggedin=0; // tells us if we are logged in (or at least think so)

   // force disconnect session if already connected
   if (ssh_session)
      ssh_disconnect_unlocked(true);
  
   if (socket.connectINET(sshhost, sshport, timeout_ms, xsink))
      return -1;
  
   // Create a session instance
   ssh_session = libssh2_session_init();
   if (!ssh_session) {
      ssh_disconnect_unlocked(true); // clean up connection
      xsink && xsink->raiseException(SSH2_ERROR, "error in libssh2_session_init(): ", strerror(errno));
      return -1;
   }

   // make sure we are in blocking mode
   set_blocking_unlocked(true);
  
   // ... start it up. This will trade welcome banners, exchange keys,
   // and setup crypto, compression, and MAC layers
   rc = libssh2_session_startup(ssh_session, socket.getSocket());
   if(rc) {
      ssh_disconnect_unlocked(true); // clean up connection
      xsink && xsink->raiseException(SSH2_ERROR, "failure establishing SSH session: %d", rc);
      return -1;
   }
  
   // check what types are available for authentifcation
   userauthlist = libssh2_userauth_list(ssh_session, sshuser, strlen(sshuser));
   // remove the info how we are actual authenticated (should be NULL anyway)
   sshauthenticatedwith = 0;

   printd(5, "userauthlist: %s\n", userauthlist);

   // set flags for use with authentification
   if (strstr(userauthlist, "publickey"))
      auth_pw |= QAUTH_PUBLICKEY;
   if (strstr(userauthlist, "password"))
      auth_pw |= QAUTH_PASSWORD;
   if (strstr(userauthlist, "keyboard-interactive"))
      auth_pw |= QAUTH_KEYBOARD_INTERACTIVE;

   // try auth 
   // try publickey if available
   if (!loggedin && (auth_pw & QAUTH_PUBLICKEY) && (sshkeys_priv && sshkeys_pub)) {
      printd(5, "SSH2Client::connect(): try pubkey auth: %s %s\n", sshkeys_priv, sshkeys_pub);
      if(libssh2_userauth_publickey_fromfile(ssh_session, sshuser, sshkeys_pub, sshkeys_priv, sshpass? sshpass: "") == 0) {
         loggedin=1;
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
      printd(5, "SSH2Client::connect(): try user/pass auth: %s/%s\n", sshuser, sshpass ? sshpass : "");
      if (!libssh2_userauth_password(ssh_session, sshuser, sshpass ? sshpass : "")) {
         loggedin=1;
         sshauthenticatedwith = "password";
         printd(5, "password authentication succeeded\n");
      }
#ifdef DEBUG
      else
         printd(5, "password authentication failed\n");
#endif
   }

   if (!loggedin && (auth_pw & QAUTH_KEYBOARD_INTERACTIVE)) {
      printd(5, "SSH2Client::connect(): try user/pass with keyboard-interactive auth: %s/%s\n", sshuser, sshpass ? sshpass : "");
      // thread thread-local storage for password for fake keyboard-interactive authentication
      keyboardPassword.set(sshpass ? sshpass : "");
      if (!libssh2_userauth_keyboard_interactive(ssh_session, sshuser, &kbd_callback)) {
         loggedin=1;
         sshauthenticatedwith = "keyboard-interactive";
         printd(5, "keyboard-interactive authentication succeeded\n");
      }
#ifdef DEBUG
      else
         printd(5, "keyboard-interactive authentication failed\n");
#endif	
   }
  
   // could we auth?
   if(!loggedin) {
      ssh_disconnect_unlocked(true); // clean up connection
      xsink && xsink->raiseException("SSH2CLIENT-AUTH-ERROR", "No proper authentication method found");
      return -1;
   }

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
	    if (check_timeout(timeout_ms, SSH2CLIENT_TIMEOUT, SSH2CLIENT_OPENSESSIONCHANNEL_ERROR, xsink))
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
	    if (check_timeout(timeout_ms, SSH2CLIENT_TIMEOUT, SSH2CLIENT_OPENDIRECTTCPIPCHANNEL_ERROR, xsink))
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
   
   struct stat sb;
   LIBSSH2_CHANNEL *channel;

   //printd(5, "sizeof(struct stat)=%d\n", sizeof(struct stat));

   while (true) {
      channel = libssh2_scp_recv(ssh_session, path, &sb);
      if (!channel) {
	 if (libssh2_session_last_error(ssh_session, 0, 0, 0) == LIBSSH2_ERROR_EAGAIN) {
	    if (check_timeout(timeout_ms, SSH2CLIENT_TIMEOUT, SSH2CLIENT_SCPGET_ERROR, xsink))
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
   
   LIBSSH2_CHANNEL *channel;

   while (true) {
      channel = libssh2_scp_send_ex(ssh_session, path, mode, size, mtime, atime);
      if (!channel) {
	 if (libssh2_session_last_error(ssh_session, 0, 0, 0) == LIBSSH2_ERROR_EAGAIN) {
	    if (check_timeout(timeout_ms, SSH2CLIENT_TIMEOUT, SSH2CLIENT_SCPPUT_ERROR, xsink))
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

// EOF //
