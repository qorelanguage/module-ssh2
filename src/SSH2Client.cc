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
#include <pwd.h>
#include <errno.h>
#include <strings.h>

#include <assert.h>
#include <unistd.h>

qore_classid_t CID_SSH2_CLIENT;

/**
 * SSH2Client constructor
 *
 * this just prefills the values for connection with hostname and port
 */
SSH2Client::SSH2Client(const char *hostname, const uint32_t port) {
  struct passwd *usrpwd;
  // remember host settings
  sshhost=strdup(hostname);
  sshport=port;
  sshuser=(char *)NULL;
  sshpass=(char *)NULL;
  sshkeys_pub=(char *)NULL;
  sshkeys_priv=(char *)NULL;
  sshauthenticatedwith=NULL; // will be filled on connect

  // prefill the user and 'estimate' the key files for rsa
  usrpwd=getpwuid(getuid());
  if(usrpwd!=NULL) {
    char thome[PATH_MAX];
    sshuser=strdup(usrpwd->pw_name);
    strncpy(thome, usrpwd->pw_dir, sizeof(thome)-1);
    sshkeys_pub=strdup(strncat(thome, "/.ssh/id_rsa.pub", sizeof(thome)-1));
    strncpy(thome, usrpwd->pw_dir, sizeof(thome)-1);
    sshkeys_priv=strdup(strncat(thome, "/.ssh/id_rsa", sizeof(thome)-1));
  }
    
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
   ssh_disconnect_unlocked(1);
   
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
int SSH2Client::ssh_disconnect_unlocked(int force, ExceptionSink *xsink) {
  if(!ssh_session && !force) {
     errno=ENOTCONN;
     xsink && xsink->raiseException("SSH2CLIENT-DISCONNECT-ERROR", "disconnect(): %s", strerror(errno));
  }

  if (ssh_session) {
     // close ssh session if not null
     libssh2_session_disconnect(ssh_session, (char*)"qore program disconnect");
     libssh2_session_free(ssh_session);
     ssh_session=NULL;
  }

  socket.close();

  return 0;
}

int SSH2Client::ssh_disconnect(int force = 0, ExceptionSink *xsink = 0) {
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

QoreObject *SSH2Client::register_channel(LIBSSH2_CHANNEL *channel) {
   AutoLocker al(m);
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
  if(!ssh_connected_unlocked()) {
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

  QORE_TRACE("SSH2Client::connect()");

  printd(1, "SSH2Client::connect(%s:%s, %dms)\n", sshhost, sshport, timeout_ms);
  
  // sanity check of data
  if (!sshuser) {
    xsink && xsink->raiseException("SSH2CLIENT-CONNECT-ERROR", "ssh user must not be NOTHING");
    return -1;
  }

  int auth_pw = 0;
  char *userauthlist;
  int rc;

  int loggedin=0; // tells us if we are logged in (or at least think so)

  // force disconnect session if already connected
  if (ssh_session)
     ssh_disconnect_unlocked(1);
  
  if (socket.connectINET(sshhost, sshport, timeout_ms, xsink))
     return -1;
  
  // Create a session instance
  ssh_session = libssh2_session_init();
  if(!ssh_session) {
    ssh_disconnect_unlocked(1); // clean up connection
    xsink && xsink->raiseException("SSH2CLIENT-CONNECT-ERROR", "error in libssh2_session_init(): ", strerror(errno));
    return -1;
  }

  // Since we have set non-blocking, tell libssh2 we are blocking
  libssh2_session_set_blocking(ssh_session, 1);
  
  // ... start it up. This will trade welcome banners, exchange keys,
  // and setup crypto, compression, and MAC layers
  rc = libssh2_session_startup(ssh_session, socket.getSocket());
  if(rc) {
    ssh_disconnect_unlocked(1); // clean up connection
    xsink && xsink->raiseException("SSH2CLIENT-CONNECT-ERROR", "failure establishing SSH session: %d", rc);
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
    ssh_disconnect_unlocked(1); // clean up connection
    xsink && xsink->raiseException("SSH2CLIENT-AUTH-ERROR", "No proper authentication method found");
    return -1;
  }

  return 0;
}

int SSH2Client::ssh_connect(int timeout_ms, ExceptionSink *xsink = 0) {
   AutoLocker al(m);

   return ssh_connect_unlocked(timeout_ms, xsink);
}

QoreHashNode *SSH2Client::ssh_info(ExceptionSink *xsink = 0) {
   AutoLocker al(m);

  QoreHashNode *ret=new QoreHashNode();
  ret->setKeyValue("ssh2host", new QoreStringNode(getHost()), xsink);
  ret->setKeyValue("ssh2port", new QoreBigIntNode(getPort()), xsink);
  ret->setKeyValue("ssh2user", new QoreStringNode(getUser()), xsink);
  //ret->setKeyValue("ssh2pass", new QoreStringNode(myself->sshpass), xsink);
  ret->setKeyValue("keyfile_priv", new QoreStringNode(getKeyPriv()), xsink);
  ret->setKeyValue("keyfile_pub", new QoreStringNode(getKeyPub()), xsink);
  ret->setKeyValue("fingerprint", fingerprint_unlocked(), xsink);
  //  ret->setKeyValue("userauthlist", myself->sshauthlist? new QoreStringNode(myself->sshauthlist): NULL, xsink);
  const char *str=getAuthenticatedWith();
  ret->setKeyValue("authenticated", str? new QoreStringNode(str): NULL, xsink);
  ret->setKeyValue("connected", get_bool_node(ssh_connected_unlocked()), xsink);

  return ret;
}












/********************
 * qore class stuff *
 ********************/

// qore-class constructor
// SSH2Client(host, [port]);
void SSH2C_constructor(class QoreObject *self, const QoreListNode *params, ExceptionSink *xsink) {
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
void SSH2C_copy(class QoreObject *self, class QoreObject *old, class SSH2Client *myself, class ExceptionSink *xsink) 
{
  xsink->raiseException("SSH2CLIENT-COPY-ERROR", "copying ssh2 connection objects is not allowed");
}


class AbstractQoreNode *SSH2C_info(class QoreObject *self, class SSH2Client *myself, const QoreListNode *params, class ExceptionSink *xsink) 
{
  if(num_params(params)) {
    xsink->raiseException("SSH2CLIENT-PARAMETER-ERROR", "getInfo() does not take any parameter");
    return NULL;
  }

  return myself->ssh_info(xsink);
}


class AbstractQoreNode *SSH2C_connect(class QoreObject *self, class SSH2Client *myself, const QoreListNode *params, class ExceptionSink *xsink) 
{
  const AbstractQoreNode *p0;
  int to=-1; // default: no timeout

  if(num_params(params) > 1) {
    xsink->raiseException("SSH2CLIENT-PARAMETER-ERROR", "use connect([timeout ms (int)])");
    return NULL;
  }

  if((p0=get_param(params, 0)) && p0->getType()!=NT_INT) {
    xsink->raiseException("SSH2CLIENT-PARAMETER-ERROR", "use connect([timeout ms (int)])");
    return NULL;
  }
  to=(p0==NULL? -1: p0->getAsInt());

  // connect
  myself->ssh_connect(to, xsink);

  // return error
  return NULL;
}

class AbstractQoreNode *SSH2C_disconnect(class QoreObject *self, class SSH2Client *myself, const QoreListNode *params, class ExceptionSink *xsink) 
{
  if(num_params(params)) {
    xsink->raiseException("SSH2CLIENT-PARAMETER-ERROR", "use disconnect()");
    return NULL;
  }

  // connect
  myself->ssh_disconnect(0, xsink);

  // return error
  return NULL;
}

class AbstractQoreNode *SSH2C_setUser(class QoreObject *self, class SSH2Client *myself, const QoreListNode *params, class ExceptionSink *xsink) 
{
  const QoreStringNode *p0;

  if(num_params(params) != 1 || !(p0=test_string_param(params, 0))) {
    xsink->raiseException("SSH2CLIENT-PARAMETER-ERROR", "use setUser(username (string))");
    return NULL;
  }

  if (myself->setUser(p0->getBuffer())) {
    xsink->raiseException("SSH2CLIENT-STATUS-ERROR", "usage of setUser() is not allowed when connected");
    return NULL;
  }

  // return error
  return NULL;
}

class AbstractQoreNode *SSH2C_setPassword(class QoreObject *self, class SSH2Client *myself, const QoreListNode *params, class ExceptionSink *xsink) 
{
  const QoreStringNode *p0;

  if(num_params(params) != 1 || !(p0=test_string_param(params, 0))) {
    xsink->raiseException("SSH2CLIENT-PARAMETER-ERROR", "use setPassword(password (string))");
    return NULL;
  }

  if (myself->setPassword(p0->getBuffer())) {
    xsink->raiseException("SSH2CLIENT-STATUS-ERROR", "usage of setPassword() is not allowed when connected");
    return NULL;
  }

  // return error
  return NULL;
}


class AbstractQoreNode *SSH2C_setKeys(class QoreObject *self, class SSH2Client *myself, const QoreListNode *params, class ExceptionSink *xsink) 
{
  const QoreStringNode *p0, *p1;
  static const char* ex_param=(char*)"use setKeys(priv_key_file (string), [pub_key_file (string)]). if no pubkey it is priv_key_file.pub";

  if(num_params(params) > 2 || num_params(params) < 1) {
    xsink->raiseException("SSH2CLIENT-PARAMETER-ERROR", ex_param);
    return NULL;
  }

  p0=test_string_param(params, 0);
  p1=test_string_param(params, 1);

  if(!p0) {
    xsink->raiseException("SSH2CLIENT-PARAMETER-ERROR", ex_param);
    return NULL;
  }

  if (myself->setKeys(p0->getBuffer(), p1? p1->getBuffer(): NULL)) {
    xsink->raiseException("SSH2CLIENT-STATUS-ERROR", "usage of setKeys() is not allowed when connected");
    return NULL;
  }

  // return error
  return NULL;
}

AbstractQoreNode *SSH2C_openSessionChannel(QoreObject *self, SSH2Client *c, const QoreListNode *params, ExceptionSink *xsink) {
   LIBSSH2_CHANNEL *chan = c->openSessionChannel(xsink);
   if (!chan)
      return 0;

   return c->register_channel(chan);
}

/**
 * class init
 */
class QoreClass *initSSH2ClientClass() {
   QORE_TRACE("initSSH2Client()");

   class QoreClass *QC_SSH2_CLIENT=new QoreClass("SSH2Client", QDOM_NETWORK);
   CID_SSH2_CLIENT=QC_SSH2_CLIENT->getID();
   QC_SSH2_CLIENT->setConstructor(SSH2C_constructor);
   QC_SSH2_CLIENT->setCopy((q_copy_t)SSH2C_copy);

   QC_SSH2_CLIENT->addMethod("connect", (q_method_t)SSH2C_connect);
   QC_SSH2_CLIENT->addMethod("disconnect", (q_method_t)SSH2C_disconnect);
   QC_SSH2_CLIENT->addMethod("info", (q_method_t)SSH2C_info);

   QC_SSH2_CLIENT->addMethod("setUser", (q_method_t)SSH2C_setUser);
   QC_SSH2_CLIENT->addMethod("setPassword", (q_method_t)SSH2C_setPassword);
   QC_SSH2_CLIENT->addMethod("setKeys", (q_method_t)SSH2C_setKeys);

   QC_SSH2_CLIENT->addMethod("openSessionChannel", (q_method_t)SSH2C_openSessionChannel);

   return QC_SSH2_CLIENT;
}

// EOF //
