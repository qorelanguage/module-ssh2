/* -*- indent-tabs-mode: nil -*- */
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

#include "SFTPClient.h"

#include <memory>
#include <string>
#include <map>
#include <utility>
#include <sys/types.h>
#include <pwd.h>

#include <assert.h>
#include <unistd.h>

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

SFTPClient::SFTPClient(QoreURL &url, const uint32_t port) : SSH2Client(url, port), sftppath(0), sftp_session(0) {
  //SSH2Client::SSH2Client(hostname, port);
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

int SFTPClient::sftp_disconnect_unlocked(bool force, ExceptionSink *xsink) {
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

int SFTPClient::sftp_disconnect(bool force, ExceptionSink *xsink) {
   AutoLocker al(m);
   return sftp_disconnect_unlocked(force, xsink);
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
int SFTPClient::sftp_connect_unlocked(int timeout_ms, ExceptionSink *xsink) {
   if (sftp_session)
      sftp_disconnect_unlocked(true);

   int rc;

   rc = ssh_connect_unlocked(timeout_ms, xsink);
   if (rc)
      return rc;

   QORE_TRACE("SFTPClient::connect()");

   // init sftp session
   sftp_session = libssh2_sftp_init(ssh_session);
  
   if (!sftp_session) {
      sftp_disconnect_unlocked(true); // force shutdown
      xsink && xsink->raiseException("SFTPCLIENT-CONNECT-ERROR", "Unable to init SFTP session");
      return -1;
   }
  
   /* Since we have not set non-blocking, tell libssh2 we are blocking */
   libssh2_session_set_blocking(ssh_session, 1);

   //      do_connected_event();
  
   // get the cwd for the path
   char buff[PATH_MAX];
   // returns the amount of chars
   if(!(rc = libssh2_sftp_realpath(sftp_session, ".", buff, sizeof(buff)-1))) {
      sftp_disconnect_unlocked(true); // force shutdown
      xsink && xsink->raiseException("SFTPCLIENT-CONNECT-ERROR", "error in getting actual path: %s", strerror(errno));
      return -1;
   }
   // for safety: do end string
   buff[rc] = '\0';
   free_string(sftppath);
   sftppath = strdup(buff);
  
   return 0;
}

int SFTPClient::sftp_connect(int timeout_ms, ExceptionSink *xsink) {
   AutoLocker al(m);

   return sftp_connect_unlocked(timeout_ms, xsink);
}

BinaryNode *SFTPClient::sftp_getFile(const char *file, ExceptionSink *xsink) {
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

// EOF //
