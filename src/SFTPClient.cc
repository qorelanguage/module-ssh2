/*
  SFTPClient.cc

  libssh2 SFTP client integration into qore

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

#include <qore/Qore.h>

#include <memory>
#include <string>
#include <map>
#include <utility>
#include <sys/types.h>
#include <pwd.h>

#include <assert.h>
#include <unistd.h>

#include "SFTPClient.h"

qore_classid_t CID_SFTP_CLIENT;

/**
 * SFTPClient constructor
 *
 * this is for creating the connection to the host/port given.
 * this raises errors if the host/port cannot be resolved
 */
SFTPClient::SFTPClient(const char *hostname, const uint32_t port) : SSH2Client(hostname, port) {
  //SSH2Client::SSH2Client(hostname, port);

  sftp_session=NULL;
  sftppath=NULL;
  printd(5, "SFTPClient::SFTPClient() this=%08p\n", this);
}


/*
 * close session/connection
 * free ressources
 */
SFTPClient::~SFTPClient() {
  QORE_TRACE("SFTPClient::~SFTPClient()");
  printd(5, "SFTPClient::~SFTPClient() this=%08p\n", this);

  if(sftp_session) {
    libssh2_sftp_shutdown(sftp_session);
    sftp_session=NULL;
  }

  free_string(sftppath);
}

/*
 * cleanup
 */
void SFTPClient::deref(ExceptionSink *xsink) {
  if(ROdereference()) {
    delete this;
  }
}


int SFTPClient::sftp_connected_unlocked() {
  return (sftp_session? 1: 0);
}

int SFTPClient::sftp_connected() {
   AutoLocker al(m);
   return sftp_connected();
}

int SFTPClient::sftp_disconnect(int force = 0, ExceptionSink *xsink = 0) {
  int rc;

  // close sftp session if not null
  if(sftp_session) {
    libssh2_sftp_shutdown(sftp_session);
    sftp_session=NULL;
  }
  free_string(sftppath);

  // close ssh session if not null
  rc=ssh_disconnect(force, xsink);
 
  return rc;
}

QoreHashNode *SFTPClient::sftp_list(const char *path, ExceptionSink *xsink) {
   AutoLocker al(m);

  //ReferenceHolder<QoreListNode> lst(new QoreListNode(), xsink);
  //return lst.release();

  // no path?
  if(!sftp_connected_unlocked()) {
    return NULL;
  }

  std::string pstr;
  if(path==NULL) { // there is no path given so we use the sftp_path
    pstr=std::string(sftppath);
  }
  else if(path[0]=='/') { // absolute path, take it
    pstr=path;
  }
  else { // relative path
    pstr=std::string(sftppath)+"/"+path;
  }

  LIBSSH2_SFTP_ATTRIBUTES attrs;
  LIBSSH2_SFTP_HANDLE *dh;

  dh=libssh2_sftp_opendir(sftp_session, pstr.c_str());  
  if(!dh) {
    xsink->raiseException("SFTPCLIENT-LIST-ERROR", "cannot open '%s' as directory", pstr.c_str());
    return NULL;
  }
  ON_BLOCK_EXIT(libssh2_sftp_close_handle, dh);

  // create objects after only possible error
  QoreListNode *files=new QoreListNode();
  ReferenceHolder<QoreListNode> dirs(new QoreListNode, xsink);
  QoreListNode *links=new QoreListNode();

  char buff[PATH_MAX];
  while(libssh2_sftp_readdir(dh, buff, sizeof(buff), &attrs) > 0) {
    if(attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) {
      // contains st_mode() from sys/stat.h
      if(S_ISDIR(attrs.permissions)) {
	dirs->push(new QoreStringNode(buff));
      }
      else if(S_ISLNK(attrs.permissions)) {
	links->push(new QoreStringNode(buff));
      }
      else {
	// everything other is a file
	files->push(new QoreStringNode(buff));
      }
    }
    else {
      // no info for filetype. we take it as file
      files->push(new QoreStringNode(buff));
    }
  }

  QoreHashNode *ret=new QoreHashNode();

  ret->setKeyValue("path", new QoreStringNode(pstr.c_str()), xsink);
  // QoreListNode::sort() returns a new QoreListNode object
  ret->setKeyValue("directories", dirs->sort(), xsink);
  ret->setKeyValue("files", files->sort(), xsink);
  ret->setKeyValue("links", links->sort(), xsink);

  return ret;
}


// return 0 if ok, -1 otherwise
int SFTPClient::sftp_chmod(const char *file, const int mode, ExceptionSink *xsink) {
  int rc;
  LIBSSH2_SFTP_ATTRIBUTES attrs;
  //  LIBSSH2_SFTP_HANDLE *sftp_handle;

  AutoLocker al(m);

  // no path?
  if(!sftp_connected_unlocked()) {
    return -2;
  }

  if(!file || !strlen(file)) {
    xsink->raiseException("SFTPCLIENT-CHMOD-ERROR", "sftp_chmod(): file is NULL or empty");
    return -3;
  }

  std::string pstr;
  if(file[0]=='/') {
    pstr=std::string(file);
  }
  else {
    pstr=std::string(sftppath)+"/"+std::string(file);
  }

  // try to get stats for this file
  rc=libssh2_sftp_stat(sftp_session, pstr.c_str(), &attrs);
  if(rc<0) {
    xsink->raiseException("SFTPCLIENT-CHMOD-ERROR", "cannot get stat for '%s'", pstr.c_str());
    return rc;
  }

  // overwrite permissions
  if(!(attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS)) {
    xsink->raiseException("SFTPCLIENT-CHMOD-ERROR", "permissions not supported by sftp server");
    return -3;
  }

  // set the permissions for file only (ugo)
  unsigned long newmode=(attrs.permissions & (-1^SFTP_UGOMASK)) | (mode & SFTP_UGOMASK);
  attrs.permissions=newmode;

  // set the permissions (stat). i happens that we get a 'SFTP Protocol Error' so we check manually
  rc=libssh2_sftp_setstat(sftp_session, pstr.c_str(), &attrs);
  if(rc<0) {
    // re-read the attributes
    rc=libssh2_sftp_stat(sftp_session, pstr.c_str(), &attrs);
    // they are how they should be, so we are done
    if(rc>-1 && attrs.permissions == newmode) {
      return 0;
    }

    // ok, there was a error
    xsink->raiseException("SFTPCLIENT-CHMOD-ERROR", "cannot set new stat (permissions) for '%s'", pstr.c_str());
    return rc;
  }

  // done :D

  return rc;
}


// return 0 if ok, -1 otherwise
int SFTPClient::sftp_mkdir(const char *dir, const int mode, ExceptionSink *xsink) {
  int rc;

  AutoLocker al(m);

  // no path?
  if(!sftp_connected_unlocked()) {
    return -2;
  }

  if(!dir || !strlen(dir)) {
    xsink->raiseException("SFTPCLIENT-MKDIR-ERROR", "sftp_mkdir(): dir is NULL or empty");
    return -3;
  }

  std::string pstr;
  if(dir[0]=='/') {
    pstr=std::string(dir);
  }
  else {
    pstr=std::string(sftppath)+"/"+std::string(dir);
  }

  // TODO: use propper modes for created dir
  rc=libssh2_sftp_mkdir(sftp_session, pstr.c_str(), mode);

  return rc;
}

int SFTPClient::sftp_rmdir(const char *dir, ExceptionSink *xsink) {
  int rc;

  AutoLocker al(m);

  // no path?
  if(!sftp_connected_unlocked()) {
    xsink->raiseException("SFTPCLIENT-CONNECTION-ERROR", "not connected");
    return -2;
  }

  if(!dir || !strlen(dir)) {
    xsink->raiseException("SFTPCLIENT-MKDIR-ERROR", "sftp_rmdir(): dir is NULL or empty");
    return -3;
  }

  std::string pstr;
  if(dir[0]=='/') {
    pstr=std::string(dir);
  }
  else {
    pstr=std::string(sftppath)+"/"+std::string(dir);
  }

  rc=libssh2_sftp_rmdir(sftp_session, pstr.c_str());

  return rc;
}

int SFTPClient::sftp_rename(const char *from, const char *to, ExceptionSink *xsink) {
  int rc;

  AutoLocker al(m);

  // no path?
  if(!sftp_connected_unlocked()) {
    return -2;
  }

  if(!(from && to)) {
    return -3;
  }

  std::string fstr, tstr;
  fstr=absolute_filename(this, from);
  tstr=absolute_filename(this, to);

  rc=libssh2_sftp_rename(sftp_session, fstr.c_str(), tstr.c_str());
  return rc;
}

int SFTPClient::sftp_unlink(const char *file, ExceptionSink *xsink) {
  int rc;

  AutoLocker al(m);

  // no path?
  if(!sftp_connected_unlocked()) {
    return -2;
  }

  if(!file) {
    return -3;
  }

  std::string fstr;
  if(file[0]=='/') {
    fstr=std::string(file);
  }
  else {
    fstr=std::string(sftppath)+"/"+std::string(file);
  }

  rc=libssh2_sftp_unlink(sftp_session, fstr.c_str());

  return rc;
}



QoreStringNode *SFTPClient::sftp_chdir(const char *nwd, ExceptionSink *xsink) {
  int rc;
  char buff[PATH_MAX];
  *buff='\0';

  AutoLocker al(m);

  // no path?
  if(!sftp_connected_unlocked()) {
    return NULL;
  }

  // calc the path. if it starts with '/', replace with nwd
  std::string npath;
  if(!nwd) {
    npath=std::string(sftppath);
  }
  else if(nwd[0]=='/') {
    npath=std::string(nwd);
  }
  else {
    npath=std::string(sftppath)+"/"+std::string(nwd);
  }

  // returns the amount of chars
  rc=libssh2_sftp_realpath(sftp_session, npath.c_str(), buff, sizeof(buff)-1);
  if(rc<0) {
    xsink->raiseException("SFTPCLIENT-CHDIR-ERROR", "error in calculate path for '%s'", npath.c_str());
    return NULL;
  }

  // check if it is a directory
  //rc=libssh2_sftp_stat(path, );
  LIBSSH2_SFTP_HANDLE *dh=libssh2_sftp_opendir(sftp_session, buff);
  if(!dh) {
    xsink->raiseException("SFTPCLIENT-CHDIR-ERROR", "'%s' is no directory", buff);
    return NULL;
  }
  libssh2_sftp_closedir(dh);

  // save new path
  if(sftppath) {
    free(sftppath);
  }
  sftppath=strdup(buff);

  //  return sftp_path(xsink);
  return sftp_path_unlocked();
}

QoreStringNode *SFTPClient::sftp_path_unlocked() {
  return sftppath? new QoreStringNode(sftppath): NULL;
}

QoreStringNode *SFTPClient::sftp_path() {
   AutoLocker al(m);
   return sftp_path();
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
int SFTPClient::sftp_connect(int timeout_ms, ExceptionSink *xsink = 0) {
  int rc;

  rc=ssh_connect(timeout_ms, xsink);
  if(rc!=0) {
    return rc;
  }

  QORE_TRACE("SFTPClient::connect()");

  // init sftp session
  sftp_session = libssh2_sftp_init(ssh_session);
  
  if (!sftp_session) {
    sftp_disconnect(1); // force shutdown
    xsink && xsink->raiseException("SFTPCLIENT-CONNECT-ERROR", "Unable to init SFTP session");
    return -1;
  }
  
  /* Since we have not set non-blocking, tell libssh2 we are blocking */
  libssh2_session_set_blocking(ssh_session, 1);

  //      do_connected_event();
  
  // get the cwd for the path
  char buff[PATH_MAX];
  // returns the amount of chars
  if(!(rc=libssh2_sftp_realpath(sftp_session, ".", buff, sizeof(buff)-1))) {
    sftp_disconnect(1); // force shutdown
    xsink && xsink->raiseException("SFTPCLIENT-CONNECT-ERROR", "error in getting actual path: %s", strerror(errno));
    return NULL;
  }
  // for safety: do end string
  *(buff+rc)='\0';
  free_string(sftppath);
  sftppath=strdup(buff);
  
  return 0;
}


BinaryNode *SFTPClient::sftp_getFile(const char *file, ExceptionSink *xsink=0) {
  AutoLocker al(m);

  if(!sftp_connected_unlocked()) {
    xsink && xsink->raiseException("SFTPCLIENT-NOT-CONNECTED", "This action can only be performed if the client is connected");
    return NULL;
  }

  int rc;
  int fsize=0;
  LIBSSH2_SFTP_HANDLE *sftp_handle;
  LIBSSH2_SFTP_ATTRIBUTES attrs;

  std::string fname=absolute_filename(this, file);

  rc=libssh2_sftp_stat(sftp_session, fname.c_str(), &attrs);
  if(rc<0) {
    xsink && xsink->raiseException("SFTPCLIENT-TRANSFER-ERROR", "error stating file on server side");
    return NULL;
  }
  fsize=attrs.filesize;

  // open handle
  sftp_handle=libssh2_sftp_open(sftp_session, fname.c_str(), LIBSSH2_FXF_READ, 0);
  if(!sftp_handle) {
    xsink && xsink->raiseException("SFTPCLIENT-TRANSFER-ERROR", "error opening file on server side");
    return NULL;
  }

  // close file
  // errors can be ignored, because by the time we close, we should have already what we want
  ON_BLOCK_EXIT(libssh2_sftp_close_handle, sftp_handle);

  // create binary node for return with the size the server gave us on stat
  SimpleRefHolder<BinaryNode> bn(new BinaryNode());
  bn->preallocate(fsize);
  rc=libssh2_sftp_read(sftp_handle, (char*)bn->getPtr(), fsize);
  if(rc<0) {
    xsink && xsink->raiseException("SFTPCLIENT-TRANSFER-ERROR", "error during reading file from server");
    return NULL;
  }
  bn->setSize(rc);

  return bn.release();
}




QoreStringNode *SFTPClient::sftp_getTextFile(const char *file, ExceptionSink *xsink=0) {
  AutoLocker al(m);

  if(!sftp_connected_unlocked()) {
    xsink && xsink->raiseException("SFTPCLIENT-NOT-CONNECTED", "This action can only be performed if the client is connected");
    return NULL;
  }

  int rc;
  int fsize=0;
  LIBSSH2_SFTP_HANDLE *sftp_handle;
  LIBSSH2_SFTP_ATTRIBUTES attrs;

  std::string fname=absolute_filename(this, file);

  rc=libssh2_sftp_stat(sftp_session, fname.c_str(), &attrs);
  if(rc<0) {
    xsink && xsink->raiseException("SFTPCLIENT-TRANSFER-ERROR", "error stating file on server side");
    return NULL;
  }
  fsize=attrs.filesize;

  // open handle
  sftp_handle=libssh2_sftp_open(sftp_session, fname.c_str(), LIBSSH2_FXF_READ, 0);
  if(!sftp_handle) {
    xsink && xsink->raiseException("SFTPCLIENT-TRANSFER-ERROR", "error opening file on server side");
    return NULL;
  }

  // close file
  // errors can be ignored, because by the time we close, we should already have what we want
  ON_BLOCK_EXIT(libssh2_sftp_close_handle, sftp_handle);

  // create buffer for return with the size the server gave us on stat
  char *memptr=(char*)malloc(sizeof(char)*(fsize+1));
  ON_BLOCK_EXIT(free, memptr);

  memptr[sizeof(char)*(fsize)]='\0';

  rc=libssh2_sftp_read(sftp_handle, memptr, fsize);
  if(rc<0) {
    xsink && xsink->raiseException("SFTPCLIENT-TRANSFER-ERROR", "error during reading file from server");
    return NULL;
  }

  QoreStringNode *rn=new QoreStringNode(memptr, fsize);

  return rn;
}





// putFile(binary to put, filename on server, mode of the created file)
int SFTPClient::sftp_putFile(const BinaryNode *data, const char *fname, int mode, class ExceptionSink *xsink=0) {
  int rc;
  int size;
  LIBSSH2_SFTP_HANDLE *sftp_handle;

  AutoLocker al(m);

  if(!sftp_connected_unlocked()) {
    xsink && xsink->raiseException("SFTPCLIENT-NOT-CONNECTED", "This action can only be performed if the client is connected");
    return -1;
  }

  std::string file=absolute_filename(this, fname);

  // if this works we try to open an sftp handle on the other side
  sftp_handle=libssh2_sftp_open(sftp_session, file.c_str(), LIBSSH2_FXF_WRITE|LIBSSH2_FXF_CREAT, mode);
  if(!sftp_handle) {
    xsink && xsink->raiseException("SFTPCLIENT-TRANSFER-ERROR", "error creating file '%s' on server side", file.c_str());
    return -1;
  }

  // write in 1024 byte packages
  const char *outb=(char*)data->getPtr();
  int maxwrite=1024;
  int towrite=data->size();
  while(towrite>0) {
    size=libssh2_sftp_write(sftp_handle, outb, towrite<maxwrite? towrite: maxwrite);
    if(size<0) {
      xsink && xsink->raiseException("SFTPCLIENT-TRANSFER-ERROR", "error during transfering file: %d", size);      
      libssh2_sftp_close(sftp_handle);
      return -1;
    }
    // correct pointers
    towrite-=size;
    outb+=size;
  }

  // will return 0 on sucess
  // we check this error, because we want to be sure the file was written
  rc=libssh2_sftp_close(sftp_handle);
  if(rc < 0) {
    xsink->raiseException("SFTPCLIENT-TRANSFER-ERROR", "error in finishing transfer");
    return -1;
  }

  return size; // the bytes actually written
}

//LIBSSH2_SFTP_ATTRIBUTES 
// return:
//  0   ok
// -1   generic error on libssh2 call
// -2   no such file
// -3   not connected to server
// gives the attrs in attrs argument back
int SFTPClient::sftp_getAttributes(const char *fname, LIBSSH2_SFTP_ATTRIBUTES *attrs, ExceptionSink *xsink = 0) {
  int rc;
  char buff[PATH_MAX];

  AutoLocker al(m);

  if(!sftp_connected_unlocked()) {
    xsink && xsink->raiseException("SFTPCLIENT-NOT-CONNECTED", "This action can only be performed if the client is connected");
    return -3;
  }

  if(!fname) {
    xsink && xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "no file given");
    return -2;
  }

  std::string file=absolute_filename(this, fname);

  // get the file
  // returns the amount of chars
  if(!(rc=libssh2_sftp_realpath(sftp_session, file.c_str(), buff, sizeof(buff)-1))) {
    xsink && xsink->raiseException("SFTPCLIENT-CONNECT-ERROR", "error in getting path for '%s'", file.c_str());
    return -1;
  }

  // this path was not found
  if(!strlen(buff)) {
    return -2;
  }
  
  // stat the file
  rc=libssh2_sftp_stat(sftp_session, file.c_str(), attrs);
  if(rc<0) {
    xsink && xsink->raiseException("SFTPCLIENT-TRANSFER-ERROR", "error stating file on server side");
    return -1;
  }

  return 0;
}















/********************
 * qore class stuff *
 ********************/

// qore-class constructor
// SFTPClient([timeout]);
void SFTPC_constructor(class QoreObject *self, const QoreListNode *params, ExceptionSink *xsink) {
  QORE_TRACE("SFTPC_constructor");

  char *ex_param=(char*)"use SFTPClient(host (string), [port (int)])";

  const QoreStringNode *p0;
  const AbstractQoreNode *p1;
  int port=22; // default ssh port

  if(num_params(params) > 2 || num_params(params) < 1) {
    xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", ex_param);
    return;
  }

  if(!(p0 = test_string_param(params, 0))) {
    xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", ex_param);
    return;
  }

  // optional port
  if((p1=get_param(params, 1))) {
    if(p1->getType()!=NT_INT) {
      xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", ex_param);
      return;
    }
    port=p1->getAsInt();
  }

  // create me
  class SFTPClient *mySFTPClient=NULL;
  mySFTPClient=new SFTPClient(p0->getBuffer(), port);

  /*
  if(*xsink) {
    return;
  }
  */

  /* no init needed. there is only a connect
  // init (creates connection)
  char *errstr=myActiveMQSession->initSession();
  // error?
  if(errstr!=NULL) {
    xsink->raiseException("AMQ-SESSION-ERROR", "error in constructor: %s", errstr);
    free(errstr);
    return;
  }
  */

  self->setPrivate(CID_SFTP_CLIENT, mySFTPClient);
}

// no copy allowed
void SFTPC_copy(class QoreObject *self, class QoreObject *old, class SFTPClient *myself, class ExceptionSink *xsink) 
{
  xsink->raiseException("SFTPCLIENT-COPY-ERROR", "copying sftp connection objects is not allowed");
}


class AbstractQoreNode *SFTPC_info(class QoreObject *self, class SFTPClient *myself, const QoreListNode *params, class ExceptionSink *xsink) 
{
  if(num_params(params)) {
    xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "getInfo() does not take any parameter");
    return NULL;
  }

  /*
  QoreHashNode *ret=new QoreHashNode();
  ret->setKeyValue("sftphost", new QoreStringNode(myself->sftphost), xsink);
  ret->setKeyValue("sftpport", new QoreBigIntNode(myself->sftpport), xsink);
  ret->setKeyValue("sftpuser", new QoreStringNode(myself->sftpuser.c_str()), xsink);
  //ret->setKeyValue("sftppass", new QoreStringNode(myself->sftppass), xsink);
  ret->setKeyValue("keyfile_priv", new QoreStringNode(myself->sftpkeys_priv), xsink);
  ret->setKeyValue("keyfile_pub", new QoreStringNode(myself->sftpkeys_pub), xsink);
  ret->setKeyValue("fingerprint", myself->fingerprint(), xsink);
  ret->setKeyValue("userauthlist", myself->sftpauthlist? new QoreStringNode(myself->sftpauthlist): NULL, xsink);
  ret->setKeyValue("path", myself->sftppath? new QoreStringNode(myself->sftppath): NULL, xsink);
  ret->setKeyValue("authenticated", myself->sftpauthenticatedwith? new QoreStringNode(myself->sftpauthenticatedwith): NULL, xsink);
  //ret->setKeyValue("", new QoreStringNode(myself->), xsink);
  */

  QoreHashNode *ret=myself->ssh_info(xsink);
  if(!ret) {
    return NULL;
  }

  ret->setKeyValue("path", myself->sftppath? new QoreStringNode(myself->sftppath): NULL, xsink);

  return ret;
  //  xsink->raiseException("SFTPCLIENT-COPY-ERROR", "copying sftp connection objects is not allowed");
}

class AbstractQoreNode *SFTPC_path(class QoreObject *self, class SFTPClient *myself, const QoreListNode *params, class ExceptionSink *xsink) 
{
  if(num_params(params)) {
    xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "use path()");
    return NULL;
  }

  //  QoreStringNode *ret=myself->sftp_path(xsink);
  QoreStringNode *ret=myself->sftp_path();
  return ret;
}

class AbstractQoreNode *SFTPC_list(class QoreObject *self, class SFTPClient *myself, const QoreListNode *params, class ExceptionSink *xsink) {
  const QoreStringNode *p0=NULL;

  if((num_params(params) > 1) ||
     (num_params(params)==1 && !(p0=test_string_param(params, 0)))) {
    xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "use list([directory (string)])");
    return NULL;
  }

  QoreHashNode *ret=myself->sftp_list(p0? p0->getBuffer(): NULL, xsink);
  return ret;
}

class AbstractQoreNode *SFTPC_stat(class QoreObject *self, class SFTPClient *myself, const QoreListNode *params, class ExceptionSink *xsink) {
  const QoreStringNode *p0;

  if(num_params(params) != 1 || !(p0=test_string_param(params, 0))) {
    xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "use stat(filename (string))");
    return NULL;
  }

  LIBSSH2_SFTP_ATTRIBUTES attr;

  int rc=myself->sftp_getAttributes(p0->getBuffer(), &attr, xsink);

  if(rc<0) {
    return NULL;
  }

  QoreHashNode *ret=new QoreHashNode();
  /*
    #define LIBSSH2_SFTP_ATTR_SIZE              0x00000001
    #define LIBSSH2_SFTP_ATTR_UIDGID            0x00000002
    #define LIBSSH2_SFTP_ATTR_PERMISSIONS       0x00000004
    #define LIBSSH2_SFTP_ATTR_ACMODTIME         0x00000008
    #define LIBSSH2_SFTP_ATTR_EXTENDED          0x80000000
  */

  if(attr.flags & LIBSSH2_SFTP_ATTR_SIZE) {
    ret->setKeyValue("size", new QoreBigIntNode(attr.filesize), xsink);
  }
  if(attr.flags & LIBSSH2_SFTP_ATTR_ACMODTIME) {
    //    ret->setKeyValue("atime", new QoreBigIntNode(attr.atime), xsink);
    //    ret->setKeyValue("mtime", new QoreBigIntNode(attr.mtime), xsink);
    ret->setKeyValue("atime", new DateTimeNode((int64)attr.atime), xsink);
    ret->setKeyValue("mtime", new DateTimeNode((int64)attr.mtime), xsink);
  }
  if(attr.flags & LIBSSH2_SFTP_ATTR_UIDGID) {
    ret->setKeyValue("uid", new QoreBigIntNode(attr.uid), xsink);
    ret->setKeyValue("gid", new QoreBigIntNode(attr.gid), xsink);
  }
  if(attr.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) {
    ret->setKeyValue("permissions", new QoreStringNode(mode2str(attr.permissions)), xsink);
  }
  
  return ret;
}


class AbstractQoreNode *SFTPC_removeFile(class QoreObject *self, class SFTPClient *myself, const QoreListNode *params, class ExceptionSink *xsink) 
{
  const QoreStringNode *p0;
  if(num_params(params)!=1 || !(p0=test_string_param(params, 0))) {
    xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "use removeFile(filename (str))");
    return NULL;
  }

 int rc=myself->sftp_unlink(p0->getBuffer(), xsink);
 if(rc < 0) {
   xsink->raiseException("SFTPCLIENT-GENERIC-ERROR", "error in removing file");
   return NULL;
 }

  return NULL;
}

class AbstractQoreNode *SFTPC_rename(class QoreObject *self, class SFTPClient *myself, const QoreListNode *params, class ExceptionSink *xsink) 
{
  const char* ex_str=(char*)"use rename(oldname (str), newname (str))";

  const QoreStringNode *p0, *p1;
  if(num_params(params)!=2 || !(p0=test_string_param(params, 0)) || !(p1=test_string_param(params, 1))) {
    xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", ex_str);
    return NULL;
  }

   // will return 0 on sucess
  int rc=myself->sftp_rename(p0->getBuffer(), p1->getBuffer(), xsink);
  if(rc < 0) {
    xsink->raiseException("SFTPCLIENT-GENERIC-ERROR", "error in renaming entry '%s'", p0->getBuffer());
    return NULL;
  }

  return NULL; // no return value
}

class AbstractQoreNode *SFTPC_chmod(class QoreObject *self, class SFTPClient *myself, const QoreListNode *params, class ExceptionSink *xsink) 
{
  const QoreStringNode *p0;
  const AbstractQoreNode *p1;
  unsigned int mode;


  if(num_params(params)!=2 || !(p0=test_string_param(params, 0))) {
    xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "use chmod(file (str), mode (octal int))");
    return NULL;
  }
  
  if(!(p1=get_param(params, 1)) || p1->getType()!=NT_INT) {
    xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "mode must be a number, eg 0755 or 0644");
    return NULL;
  }
  mode=(unsigned int)p1->getAsInt();

  // check if mode is in range
  if(mode != (mode & SFTP_UGOMASK)) {
    xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "mode setting is only possible for user, group and other (no sticky bits)");
    return NULL;
  }

  // will return 0 on sucess
  int rc=myself->sftp_chmod(p0->getBuffer(), mode, xsink);
  if(rc < 0) {
    //xsink->raiseException("SFTPCLIENT-GENERIC-ERROR", "error in change mode");
  }

  return NULL; // no return value
}

class AbstractQoreNode *SFTPC_getFile(class QoreObject *self, class SFTPClient *myself, const QoreListNode *params, class ExceptionSink *xsink) 
{
  /*
  if(!myself->sftp_connected()) {
    xsink->raiseException("SFTPCLIENT-NOT-CONNECTED", "This action can only be performed if the client is connected");
    return NULL;
  }
  */

  const QoreStringNode *p0;

  if(num_params(params)!=1 || !(p0=test_string_param(params, 0))) {
    xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "use getFile(file (str))");
    return NULL;
  }

  return myself->sftp_getFile(p0->getBuffer(), xsink);

}


class AbstractQoreNode *SFTPC_getTextFile(class QoreObject *self, class SFTPClient *myself, const QoreListNode *params, class ExceptionSink *xsink) {
  const QoreStringNode *p0;

  if(num_params(params)!=1 || !(p0=test_string_param(params, 0))) {
    xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "use getFile(file (str))");
    return NULL;
  }

  return myself->sftp_getTextFile(p0->getBuffer(), xsink);

}

// putFile(date (binarynode), filename (string), [mode (int,octal)])
class AbstractQoreNode *SFTPC_putFile(class QoreObject *self, class SFTPClient *myself, const QoreListNode *params, class ExceptionSink *xsink) 
{
  const AbstractQoreNode *p2;
  const QoreStringNode *p1;
  int rc;
  // defaultmode 0644
  int mode=LIBSSH2_SFTP_S_IRUSR|LIBSSH2_SFTP_S_IWUSR|
    LIBSSH2_SFTP_S_IRGRP|
    LIBSSH2_SFTP_S_IROTH;

  if(num_params(params) < 2 || num_params(params) > 3 || !(p1=test_string_param(params, 1))) {
    xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "use putFile(data (binary), filename (string), [mode (octal int)])");
    return NULL;
  }
  
  // get the mode if given
  if((p2=get_param(params, 2))) {
    if(p2->getType()!=NT_INT) {
      xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "mode must be an octal number, eg 0755");
      return NULL;
    }
    mode=p2->getAsInt();
  }

  // data is a binary node
  const BinaryNode *bn=test_binary_param(params, 0);
  if(!bn) {
    xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "Data must be a Binary object.");
    return NULL;
  }

  // transfer the file
  rc=myself->sftp_putFile(bn, p1->getBuffer(), mode, xsink);
  // error?
  if(rc<0) {
    return NULL;
  }

  return new QoreBigIntNode(rc);

}



class AbstractQoreNode *SFTPC_mkdir(class QoreObject *self, class SFTPClient *myself, const QoreListNode *params, class ExceptionSink *xsink) 
{
  const QoreStringNode *p0;
  const AbstractQoreNode *p1;
  // defaultmode 0755
  int mode=LIBSSH2_SFTP_S_IRWXU|
    LIBSSH2_SFTP_S_IRGRP|LIBSSH2_SFTP_S_IXGRP|
    LIBSSH2_SFTP_S_IROTH|LIBSSH2_SFTP_S_IXOTH;


  if(!(p0=test_string_param(params, 0)) || num_params(params)<1 || num_params(params)>2) {
    xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "use mkdir(new dir (str), [mode (octal int)])");
    return NULL;
  }
  
  if((p1=get_param(params, 1))) {
    if(p1->getType()!=NT_INT) {
      xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "mode must be an octal number, eg 0755");
      return NULL;
    }
    mode=p1->getAsInt();
  }


  // will return 0 on sucess
  int rc=myself->sftp_mkdir(p0->getBuffer(), mode, xsink);
  if(rc < 0) {
    xsink->raiseException("SFTPCLIENT-GENERIC-ERROR", "error in creating directory");
  }

  return NULL; // no return value
}


class AbstractQoreNode *SFTPC_rmdir(class QoreObject *self, class SFTPClient *myself, const QoreListNode *params, class ExceptionSink *xsink) 
{
  const QoreStringNode *p0;

  if(!(p0=test_string_param(params, 0))) {
    xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "use rmdir(dir to delete (str))");
    return NULL;
  }
  
  // will return 0 on sucess
  int rc=myself->sftp_rmdir(p0->getBuffer(), xsink);
  if(rc < 0) {
    xsink->raiseException("SFTPCLIENT-GENERIC-ERROR", "error in removing directory");
  }

  return NULL; // no return value
}



// returns NOTHING if the chdir was not working
class AbstractQoreNode *SFTPC_chdir(class QoreObject *self, class SFTPClient *myself, const QoreListNode *params, class ExceptionSink *xsink) 
{
  const QoreStringNode *p0;

  if(!(p0=test_string_param(params, 0))) {
    xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "use chdir(new dir (str))");
    return NULL;
  }

  QoreStringNode *ret=myself->sftp_chdir(p0? p0->getBuffer(): NULL, xsink);
  return ret;
}


class AbstractQoreNode *SFTPC_connect(class QoreObject *self, class SFTPClient *myself, const QoreListNode *params, class ExceptionSink *xsink) 
{
  const AbstractQoreNode *p0;
  int to=-1; // default: no timeout

  if(num_params(params) > 1) {
    xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "use connect([timeout ms (int)])");
    return NULL;
  }

  if((p0=get_param(params, 0)) && p0->getType()!=NT_INT) {
    xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "use connect([timeout ms (int)])");
    return NULL;
  }
  to=(p0==NULL? -1: p0->getAsInt());

  // connect
  myself->sftp_connect(to, xsink);

  // return error
  return NULL;
}

class AbstractQoreNode *SFTPC_disconnect(class QoreObject *self, class SFTPClient *myself, const QoreListNode *params, class ExceptionSink *xsink) 
{
  if(num_params(params)) {
    xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "use disconnect()");
    return NULL;
  }

  // dis connect
  myself->sftp_disconnect(0, xsink);

  // return error
  return NULL;
}




extern class AbstractQoreNode *SSH2C_setUser(class QoreObject *, class SSH2Client *, const QoreListNode *, class ExceptionSink *);
extern class AbstractQoreNode *SSH2C_setPassword(class QoreObject *, class SSH2Client *, const QoreListNode *, class ExceptionSink *);
extern class AbstractQoreNode *SSH2C_setKeys(class QoreObject *, class SSH2Client *, const QoreListNode *, class ExceptionSink *);


/**
 * class init
 */
class QoreClass *initSFTPClientClass() {
   QORE_TRACE("initSFTPClient()");

   class QoreClass *QC_SFTP_CLIENT=new QoreClass("SFTPClient", QDOM_NETWORK);
   CID_SFTP_CLIENT=QC_SFTP_CLIENT->getID();
   QC_SFTP_CLIENT->setConstructor(SFTPC_constructor);
   QC_SFTP_CLIENT->setCopy((q_copy_t)SFTPC_copy);

   QC_SFTP_CLIENT->addMethod("connect", (q_method_t)SFTPC_connect);
   QC_SFTP_CLIENT->addMethod("disconnect", (q_method_t)SFTPC_disconnect);
   QC_SFTP_CLIENT->addMethod("info", (q_method_t)SFTPC_info);

   // methods comming from SSH2Client class
   QC_SFTP_CLIENT->addMethod("setUser", (q_method_t)SSH2C_setUser);
   QC_SFTP_CLIENT->addMethod("setPassword", (q_method_t)SSH2C_setPassword);
   QC_SFTP_CLIENT->addMethod("setKeys", (q_method_t)SSH2C_setKeys);

   QC_SFTP_CLIENT->addMethod("path", (q_method_t)SFTPC_path);

   QC_SFTP_CLIENT->addMethod("chdir", (q_method_t)SFTPC_chdir);
   QC_SFTP_CLIENT->addMethod("list", (q_method_t)SFTPC_list);
   QC_SFTP_CLIENT->addMethod("stat", (q_method_t)SFTPC_stat);

   QC_SFTP_CLIENT->addMethod("mkdir", (q_method_t)SFTPC_mkdir);
   QC_SFTP_CLIENT->addMethod("rmdir", (q_method_t)SFTPC_rmdir);

   QC_SFTP_CLIENT->addMethod("removeFile", (q_method_t)SFTPC_removeFile);
   QC_SFTP_CLIENT->addMethod("rename", (q_method_t)SFTPC_rename);
   QC_SFTP_CLIENT->addMethod("chmod", (q_method_t)SFTPC_chmod);

   QC_SFTP_CLIENT->addMethod("putFile", (q_method_t)SFTPC_putFile);
   QC_SFTP_CLIENT->addMethod("getFile", (q_method_t)SFTPC_getFile);
   QC_SFTP_CLIENT->addMethod("getTextFile", (q_method_t)SFTPC_getTextFile);

   return QC_SFTP_CLIENT;
}




// EOF //
