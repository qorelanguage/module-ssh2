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
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#include <assert.h>
#include <unistd.h>

static const char *SFTPCLIENT_CONNECT_ERROR  = "SFTPCLIENT-CONNECT-ERROR";
static const char *SFTPCLIENT_NOT_CONNECTED  = "SFTPCLIENT-NOT-CONNECTED";

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
   if (ROdereference()) {
      delete this;
   }
}


int SFTPClient::sftp_connected_unlocked() {
   return (sftp_session ? 1: 0);
}

int SFTPClient::sftp_connected() {
   AutoLocker al(m);
   return sftp_connected_unlocked();
}

int SFTPClient::sftp_disconnect_unlocked(bool force, ExceptionSink *xsink) {
   int rc;

   // close sftp session if not null
   if (sftp_session) {
      libssh2_sftp_shutdown(sftp_session);
      sftp_session = NULL;
   }
   free_string(sftppath);

   // close ssh session if not null
   rc = ssh_disconnect_unlocked(force, xsink);

   return rc;
}

int SFTPClient::sftp_disconnect(bool force, ExceptionSink *xsink) {
   AutoLocker al(m);
   return sftp_disconnect_unlocked(force, xsink);
}

QoreHashNode *SFTPClient::sftp_list(const char *path, ExceptionSink *xsink) {
   AutoLocker al(m);

   // no path?
   if (!sftp_connected_unlocked()) {
      xsink->raiseException(SFTPCLIENT_NOT_CONNECTED, "the SFTPClient object is not connected");
      return 0;
   }

   std::string pstr;
   if (!path) // there is no path given so we use the sftp_path
      pstr = std::string(sftppath);
   else if (path[0] == '/') // absolute path, take it
      pstr = path;
   else // relative path
      pstr = std::string(sftppath) + "/" + path;

   LIBSSH2_SFTP_HANDLE *dh = libssh2_sftp_opendir(sftp_session, pstr.c_str());  
   if (!dh) {
      xsink->raiseException("SFTPCLIENT-LIST-ERROR", "cannot open '%s' as directory", pstr.c_str());
      return 0;
   }
   ON_BLOCK_EXIT(libssh2_sftp_close_handle, dh);

   // create objects after only possible error
   ReferenceHolder<QoreListNode> files(new QoreListNode, xsink);
   ReferenceHolder<QoreListNode> dirs(new QoreListNode, xsink);
   ReferenceHolder<QoreListNode> links(new QoreListNode, xsink);

   char buff[PATH_MAX];
   LIBSSH2_SFTP_ATTRIBUTES attrs;

   while (libssh2_sftp_readdir(dh, buff, sizeof(buff), &attrs) > 0) {
      if (attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) {
         // contains st_mode() from sys/stat.h
         if (S_ISDIR(attrs.permissions))
            dirs->push(new QoreStringNode(buff));
#ifdef S_ISLNK
         else if (S_ISLNK(attrs.permissions))
            links->push(new QoreStringNode(buff));
#endif
         else // everything else is a file
            files->push(new QoreStringNode(buff));
      }
      else
         // no info for filetype. we take it as file
         files->push(new QoreStringNode(buff));
   }

   QoreHashNode *ret = new QoreHashNode;

   ret->setKeyValue("path", new QoreStringNode(pstr.c_str()), xsink);
   // QoreListNode::sort() returns a new QoreListNode object
   ret->setKeyValue("directories", dirs->sort(), xsink);
   ret->setKeyValue("files", files->sort(), xsink);
   ret->setKeyValue("links", links->sort(), xsink);

   return ret;
}

// return 0 if ok, -1 otherwise
int SFTPClient::sftp_chmod(const char *file, const int mode, ExceptionSink *xsink) {
   static const char *SFTPCLIENT_CHMOD_ERROR = "SFTPCLIENT-CHMOD-ERROR";

   assert(file);

   if (!strlen(file)) {
      xsink->raiseException(SFTPCLIENT_CHMOD_ERROR, "file argument is empty");
      return -3;
   }

   AutoLocker al(m);

   // no path?
   if (!sftp_connected_unlocked()) {
      xsink->raiseException(SFTPCLIENT_NOT_CONNECTED, "the SFTPClient object is not connected");
      return -2;
   }

   std::string pstr;
   if (file[0] == '/')
      pstr = std::string(file);
   else
      pstr = std::string(sftppath)+"/"+std::string(file);

   // try to get stats for this file
   LIBSSH2_SFTP_ATTRIBUTES attrs;
   int rc = libssh2_sftp_stat(sftp_session, pstr.c_str(), &attrs);
   if (rc < 0) {
      do_session_err_unlocked(xsink, "SFTPClient::chmod() raised an error in libssh2_sftp_stat(%s)", pstr.c_str());
      return rc;
   }

   // overwrite permissions
   if (!(attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS)) {
      xsink->raiseException(SFTPCLIENT_CHMOD_ERROR, "permissions not supported by sftp server");
      return -3;
   }

   // set the permissions for file only (ugo)
   unsigned long newmode = (attrs.permissions & (-1^SFTP_UGOMASK)) | (mode & SFTP_UGOMASK);
   attrs.permissions = newmode;

   // set the permissions (stat). it happens that we get a 'SFTP Protocol Error' so we check manually
   rc = libssh2_sftp_setstat(sftp_session, pstr.c_str(), &attrs);
   if (rc < 0) {
      // re-read the attributes
      rc = libssh2_sftp_stat(sftp_session, pstr.c_str(), &attrs);
      // they are how they should be, so we are done
      if (rc >= 0 && attrs.permissions == newmode)
         return 0;

      // ok, there was a error
      do_session_err_unlocked(xsink, "SFTPClient::chmod() raised an error in libssh2_sftp_setstat(%s)", pstr.c_str());
   }

   return rc;
}

// return 0 if ok, -1 otherwise
int SFTPClient::sftp_mkdir(const char *dir, const int mode, ExceptionSink *xsink) {
   assert(dir);

   if (!strlen(dir)) {
      xsink->raiseException("SFTPCLIENT-MKDIR-ERROR", "directory name is empty");
      return -3;
   }

   AutoLocker al(m);

   // no path?
   if (!sftp_connected_unlocked()) {
      xsink->raiseException(SFTPCLIENT_NOT_CONNECTED, "the SFTPClient object is not connected");
      return -2;
   }

   std::string pstr;
   if (dir[0] == '/')
      pstr = std::string(dir);
   else
      pstr = std::string(sftppath) + "/" + std::string(dir);

   // TODO: use proper modes for created dir
   int rc = libssh2_sftp_mkdir(sftp_session, pstr.c_str(), mode);
   if (rc < 0)
      do_session_err_unlocked(xsink, "SFTPClient::mkdir() raised an error in libssh2_sftp_mkdir(%s)", pstr.c_str());

   return rc;
}

int SFTPClient::sftp_rmdir(const char *dir, ExceptionSink *xsink) {
   assert(dir);

   if (!strlen(dir)) {
      xsink->raiseException("SFTPCLIENT-MKDIR-ERROR", "directory name is empty");
      return -3;
   }

   AutoLocker al(m);

   // no path?
   if (!sftp_connected_unlocked()) {
      xsink->raiseException(SFTPCLIENT_NOT_CONNECTED, "the SFTPClient object is not connected");
      return -2;
   }

   std::string pstr;
   if (dir[0] == '/')
      pstr = std::string(dir);
   else
      pstr = std::string(sftppath) + "/" + std::string(dir);

   int rc = libssh2_sftp_rmdir(sftp_session, pstr.c_str());
   if (rc < 0)
      do_session_err_unlocked(xsink, "SFTPClient::rmdir() raised an error in libssh2_sftp_rmdir(%s)", pstr.c_str());

   return rc;
}

int SFTPClient::sftp_rename(const char *from, const char *to, ExceptionSink *xsink) {
   assert(from && to);

   AutoLocker al(m);

   // no path?
   if(!sftp_connected_unlocked()) {
      xsink->raiseException(SFTPCLIENT_NOT_CONNECTED, "not connected");
      return -2;
   }

   std::string fstr, tstr;
   fstr = absolute_filename(this, from);
   tstr = absolute_filename(this, to);

   int rc = libssh2_sftp_rename(sftp_session, fstr.c_str(), tstr.c_str());
   if (rc < 0)
      do_session_err_unlocked(xsink, "SFTPClient::rename() raised an error in libssh2_sftp_rename(%s, %s)", fstr.c_str(), tstr.c_str());

   return rc;
}

int SFTPClient::sftp_unlink(const char *file, ExceptionSink *xsink) {
   assert(file);

   AutoLocker al(m);

   // no path?
   if(!sftp_connected_unlocked()) {
      xsink->raiseException(SFTPCLIENT_NOT_CONNECTED, "not connected");
      return -2;
   }

   std::string fstr;
   if (file[0] == '/')
      fstr = std::string(file);
   else
      fstr = std::string(sftppath) + "/" + std::string(file);

   int rc = libssh2_sftp_unlink(sftp_session, fstr.c_str());
   if (rc < 0)
      do_session_err_unlocked(xsink, "SFTPClient::removeFile() raised an error in libssh2_sftp_unlink(%s)", fstr.c_str());

   return rc;
}

QoreStringNode *SFTPClient::sftp_chdir(const char *nwd, ExceptionSink *xsink) {
   char buff[PATH_MAX];
   *buff='\0';

   AutoLocker al(m);

   // no path?
   if (!sftp_connected_unlocked()) {
      xsink->raiseException(SFTPCLIENT_NOT_CONNECTED, "not connected");
      return NULL;
   }

   // calc the path. if it starts with '/', replace with nwd
   std::string npath;
   if (!nwd)
      npath = std::string(sftppath);
   else if(nwd[0] == '/')
      npath = std::string(nwd);
   else
      npath = std::string(sftppath) + "/" + std::string(nwd);

   // returns the amount of chars
   int rc = libssh2_sftp_realpath(sftp_session, npath.c_str(), buff, sizeof(buff)-1);
   if (rc < 0) {
      xsink->raiseException("SFTPCLIENT-CHDIR-ERROR", "SFTPClient::chdir() raised an error in calculating path for '%s'", npath.c_str());
      return NULL;
   }

   // check if it is a directory
   //rc=libssh2_sftp_stat(path, );
   LIBSSH2_SFTP_HANDLE *dh=libssh2_sftp_opendir(sftp_session, buff);
   if(!dh) {
      xsink->raiseException("SFTPCLIENT-CHDIR-ERROR", "'%s' is not a directory", buff);
      return NULL;
   }
   libssh2_sftp_closedir(dh);

   // save new path
   if (sftppath)
      free(sftppath);
   sftppath = strdup(buff);

   return new QoreStringNode(sftppath);
}

QoreStringNode *SFTPClient::sftp_path_unlocked() {
   return sftppath ? new QoreStringNode(sftppath) : NULL;
}

QoreStringNode *SFTPClient::sftp_path() {
   AutoLocker al(m);
   return sftp_path_unlocked();
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
      xsink && xsink->raiseException(SFTPCLIENT_CONNECT_ERROR, "Unable to init SFTP session");
      return -1;
   }
  
   /* Since we have not set non-blocking, tell libssh2 we are blocking */
   libssh2_session_set_blocking(ssh_session, 1);

   //      do_connected_event();
  
   // get the cwd for the path
   char buff[PATH_MAX];
   // returns the amount of chars
   if(!(rc = libssh2_sftp_realpath(sftp_session, ".", buff, sizeof(buff)-1))) {
      if (xsink)
         do_session_err_unlocked(xsink, "SFTPClient::connect() raised an error in libssh2_sftp_realpath()");
      sftp_disconnect_unlocked(true); // force shutdown
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

   if (!sftp_connected_unlocked()) {
      xsink->raiseException(SFTPCLIENT_NOT_CONNECTED, "not connected");
      return NULL;
   }

   std::string fname = absolute_filename(this, file);

   LIBSSH2_SFTP_ATTRIBUTES attrs;
   int rc = libssh2_sftp_stat(sftp_session, fname.c_str(), &attrs);
   if (rc < 0) {
      do_session_err_unlocked(xsink, "SFTPClient::getFile() raised an error in libssh2_sftp_stat(%s)", fname.c_str());
      return NULL;
   }
   size_t fsize = attrs.filesize;

   // open handle
   LIBSSH2_SFTP_HANDLE *sftp_handle = libssh2_sftp_open(sftp_session, fname.c_str(), LIBSSH2_FXF_READ, 0);
   if (!sftp_handle) {
      do_session_err_unlocked(xsink, "SFTPClient::getFile() raised an error in libssh2_sftp_open(%s)", fname.c_str());
      return NULL;
   }

   // close file
   // errors can be ignored, because by the time we close, we should have already what we want
   ON_BLOCK_EXIT(libssh2_sftp_close_handle, sftp_handle);

   // create binary node for return with the size the server gave us on stat
   SimpleRefHolder<BinaryNode> bn(new BinaryNode());
   bn->preallocate(fsize);

   size_t tot = 0;
   while (true) {
      rc = libssh2_sftp_read(sftp_handle, (char*)bn->getPtr() + tot, fsize - tot);
      if (rc < 0) {
         do_session_err_unlocked(xsink, "SFTPClient::getFile() raised an error in libssh2_sftp_read(%ld) total read: %ld while reading '%s' size %ld", fsize - tot, tot, fname.c_str(), fsize);
         return NULL;
      }
      if (rc)
         tot += rc;
      if (tot >= fsize)
         break;
   }
   bn->setSize(tot);

   return bn.release();
}

QoreStringNode *SFTPClient::sftp_getTextFile(const char *file, ExceptionSink *xsink) {
   AutoLocker al(m);

   if (!sftp_connected_unlocked()) {
      xsink->raiseException(SFTPCLIENT_NOT_CONNECTED, "This action can only be performed if the client is connected");
      return NULL;
   }

   std::string fname = absolute_filename(this, file);

   LIBSSH2_SFTP_ATTRIBUTES attrs;
   int rc = libssh2_sftp_stat(sftp_session, fname.c_str(), &attrs);
   if (rc < 0) {
      do_session_err_unlocked(xsink, "SFTPClient::getTextFile() raised an error in libssh2_sftp_stat(%s)", fname.c_str());
      return NULL;
   }
   size_t fsize = attrs.filesize;
   
   // open handle
   LIBSSH2_SFTP_HANDLE *sftp_handle = libssh2_sftp_open(sftp_session, fname.c_str(), LIBSSH2_FXF_READ, 0);
   if (!sftp_handle) {
      do_session_err_unlocked(xsink, "SFTPClient::getTextFile() raised an error in libssh2_sftp_open(%s)", fname.c_str());
      return NULL;
   }

   // close file
   // errors can be ignored, because by the time we close, we should already have what we want
   ON_BLOCK_EXIT(libssh2_sftp_close_handle, sftp_handle);

   // create buffer for return with the size the server gave us on stat + 1 byte for termination char
   SimpleRefHolder<QoreStringNode> str(new QoreStringNode);
   str->allocate(fsize + 1);
   
   size_t tot = 0;
   while (true) {
      rc = libssh2_sftp_read(sftp_handle, (char *)str->getBuffer() + tot, fsize - (size_t)tot);
      if (rc < 0) {
         do_session_err_unlocked(xsink, "SFTPClient::getTextFile() raised an error in libssh2_sftp_read(%ld) total read: %ld while reading '%s' size %ld", fsize - tot, tot, fname.c_str(), fsize);
         return NULL;
      }
      if (rc)
         tot += rc;
      if (tot >= fsize)
         break;
   }
   str->terminate(tot);

   return str.release();
}

// putFile(binary to put, filename on server, mode of the created file)
qore_size_t SFTPClient::sftp_putFile(const char *outb, qore_size_t towrite, const char *fname, int mode, ExceptionSink *xsink) {
   AutoLocker al(m);

   if (!sftp_connected_unlocked()) {
      xsink->raiseException(SFTPCLIENT_NOT_CONNECTED, "This action can only be performed if the client is connected");
      return -1;
   }

   std::string file = absolute_filename(this, fname);

   // if this works we try to open an sftp handle on the other side
   LIBSSH2_SFTP_HANDLE *sftp_handle = libssh2_sftp_open_ex(sftp_session, file.c_str(), file.size(), LIBSSH2_FXF_WRITE|LIBSSH2_FXF_CREAT|LIBSSH2_FXF_TRUNC, mode, LIBSSH2_SFTP_OPENFILE);
   if (!sftp_handle) {
      do_session_err_unlocked(xsink, "SFTPClient::putFile() raised an error in libssh2_sftp_open_ex(%s)", file.c_str());
      return -1;
   }

   qore_size_t size = 0;
   while (size < towrite) {
      ssize_t rc = libssh2_sftp_write(sftp_handle, outb, towrite - size);
      if (rc < 0) { 
         do_session_err_unlocked(xsink, "SFTPClient::putFile() raised an error in libssh2_sftp_open_ex(%ld) while writing '%s', total written: %ld, total to write: %ld", towrite - size, file.c_str(), size, towrite);
         libssh2_sftp_close(sftp_handle);
         return -1;
      }
      size += rc;
   }

   // will return 0 on sucess
   // we check this error, because we want to be sure the file was written
   int rc = libssh2_sftp_close(sftp_handle);
   if (rc < 0) {
      do_session_err_unlocked(xsink, "SFTPClient::putFile() raised an error in libssh2_sftp_close() while closing '%s'", file.c_str());
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
int SFTPClient::sftp_getAttributes(const char *fname, LIBSSH2_SFTP_ATTRIBUTES *attrs, ExceptionSink *xsink) {
   assert(fname);

   AutoLocker al(m);

   if (!sftp_connected_unlocked()) {
      xsink->raiseException(SFTPCLIENT_NOT_CONNECTED, "This action can only be performed if the client is connected");
      return -3;
   }

   if (!fname) {
      xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "no file given");
      return -2;
   }

   std::string file = absolute_filename(this, fname);
 
   // stat the file
   int rc = libssh2_sftp_stat(sftp_session, file.c_str(), attrs);
   if (rc < 0) {
      // check if the file does not exist
      if (libssh2_session_last_errno(ssh_session) == LIBSSH2_ERROR_SFTP_PROTOCOL
          && libssh2_sftp_last_error(sftp_session) == LIBSSH2_FX_NO_SUCH_FILE)
         return -2;

      do_session_err_unlocked(xsink, "SFTPClient::stat() raised an error in libssh2_sftp_stat(%s)", file.c_str());
      return -1;
   }

   return 0;
}

void SFTPClient::do_session_err_unlocked(ExceptionSink *xsink, const char *fmt, ...) {
   va_list args;
   QoreStringNode *desc = new QoreStringNode;

   while (true) {
      va_start(args, fmt);
      int rc = desc->vsprintf(fmt, args);
      va_end(args);
      if (!rc)
         break;
   }

   int err = libssh2_session_last_errno(ssh_session);
   if (err == LIBSSH2_ERROR_SFTP_PROTOCOL) {
      unsigned long serr = libssh2_sftp_last_error(sftp_session);

      desc->sprintf(": libssh2 returned sftp error %lu: ", serr);
      switch (serr) {
         case LIBSSH2_FX_OK:
            desc->concat("success");
            break;
         case LIBSSH2_FX_EOF:
            desc->concat("EOF: end of file");
            break;
         case LIBSSH2_FX_NO_SUCH_FILE:
            desc->concat("file does not exist");
            break;
         case LIBSSH2_FX_PERMISSION_DENIED:
            desc->concat("permission denied");
            break;
         case LIBSSH2_FX_FAILURE:
            desc->concat("command failed");
            break;
         case LIBSSH2_FX_BAD_MESSAGE:
            desc->concat("bad message");
            break;
         case LIBSSH2_FX_NO_CONNECTION:
            desc->concat("no connection");
            break;
         case LIBSSH2_FX_CONNECTION_LOST:
            desc->concat("connection lost");
            break;
         case LIBSSH2_FX_OP_UNSUPPORTED:
            desc->concat("sshd sftp server does not support this operation");
            break;
         case LIBSSH2_FX_INVALID_HANDLE:
            desc->concat("invalid handle");
            break;
         case LIBSSH2_FX_NO_SUCH_PATH:
            desc->concat("path does not exist");
            break;
         case LIBSSH2_FX_FILE_ALREADY_EXISTS:
            desc->concat("file already exists");
            break;
         case LIBSSH2_FX_WRITE_PROTECT:
            desc->concat("write protected");
            break;
         case LIBSSH2_FX_NO_MEDIA:
            desc->concat("no media");
            break;
         case LIBSSH2_FX_NO_SPACE_ON_FILESYSTEM:
            desc->concat("filesystem full");
            break;
         case LIBSSH2_FX_QUOTA_EXCEEDED:
            desc->concat("quota exceeddd");
            break;
         case LIBSSH2_FX_UNKNOWN_PRINCIPAL:
            desc->concat("unknown principal");
            break;
         case LIBSSH2_FX_LOCK_CONFLICT:
            desc->concat("lock conflict");
            break;
         case LIBSSH2_FX_DIR_NOT_EMPTY:
            desc->concat("directory not empty");
            break;
         case LIBSSH2_FX_NOT_A_DIRECTORY:
            desc->concat("not a directory");
            break;
         case LIBSSH2_FX_INVALID_FILENAME:
            desc->concat("invalid filename");
            break;
         case LIBSSH2_FX_LINK_LOOP:
            desc->concat("link loop");
            break;
         default:
            desc->sprintf("unknown error code %ld", serr);
            break;
      }
   }
   else
      desc->sprintf(": libssh2 returned error %d: %s", err, get_session_err_unlocked());

   xsink->raiseException(SSH2_ERROR, desc);
}

QoreHashNode *SFTPClient::sftp_info() {
   AutoLocker al(m);
   QoreHashNode *h = ssh_info_intern();
   h->setKeyValue("path", sftppath? new QoreStringNode(sftppath) : 0, 0);

   return h;
}
