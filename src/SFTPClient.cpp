/* -*- indent-tabs-mode: nil -*- */
/*
  SFTPClient.cc

  libssh2 SFTP client integration into qore

  Copyright 2009 Wolfgang Ritzinger
  Copyright 2010 - 2013 Qore Technologies, sro

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

static const char* SFTPCLIENT_CONNECT_ERROR = "SFTPCLIENT-CONNECT-ERROR";
static const char* SFTPCLIENT_NOT_CONNECTED = "SFTPCLIENT-NOT-CONNECTED";
static const char* SFTPCLIENT_TIMEOUT = "SFTPCLIENT-TIMEOUT";

/**
 * SFTPClient constructor
 *
 * this is for creating the connection to the host/port given.
 * this raises errors if the host/port cannot be resolved
 */
SFTPClient::SFTPClient(const char* hostname, const uint32_t port) : SSH2Client(hostname, port), sftp_session(0) {
   printd(5, "SFTPClient::SFTPClient() this: %p\n", this);
}

SFTPClient::SFTPClient(QoreURL &url, const uint32_t port) : SSH2Client(url, port), sftp_session(0) {
   printd(5, "SFTPClient::SFTPClient() this: %p\n", this);
}

/*
 * close session/connection
 * free ressources
 */
SFTPClient::~SFTPClient() {
   QORE_TRACE("SFTPClient::~SFTPClient()");
   printd(5, "SFTPClient::~SFTPClient() this: %p\n", this);

   do_shutdown();
}

void SFTPClient::do_shutdown(int timeout_ms, ExceptionSink* xsink) {
   if (sftp_session) {
      BlockingHelper bh(this);
         
      int rc;
      while ((rc = libssh2_sftp_shutdown(sftp_session)) == LIBSSH2_ERROR_EAGAIN) {
         if (waitsocket_unlocked(xsink, SFTPCLIENT_TIMEOUT, "SFTPCLIENT-DISCONNECT", "SFTPClient::disconnect", timeout_ms))
            break;
      }

      // note: we could have a memory leak here if libssh2_sftp_shutdown timed out,
      // but there doesn't seem to be any other way to free the memory
      sftp_session = 0;
   }
}

/*
 * cleanup
 */
void SFTPClient::deref(ExceptionSink* xsink) {
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

int SFTPClient::sftp_disconnect_unlocked(bool force, int timeout_ms, ExceptionSink* xsink) {
   int rc;

   // close sftp session if not null
   do_shutdown(timeout_ms, xsink);
   sftppath.clear();

   // close ssh session if not null
   rc = ssh_disconnect_unlocked(force, timeout_ms, xsink);

   return rc;
}

int SFTPClient::sftp_disconnect(bool force, int timeout_ms, ExceptionSink* xsink) {
   AutoLocker al(m);
   return sftp_disconnect_unlocked(force, timeout_ms, xsink);
}

QoreHashNode *SFTPClient::sftp_list(const char* path, int timeout_ms, ExceptionSink* xsink) {
   AutoLocker al(m);

   // no path?
   if (!sftp_connected_unlocked()) {
      xsink->raiseException(SFTPCLIENT_NOT_CONNECTED, "the SFTPClient object is not connected");
      return 0;
   }

   std::string pstr;
   if (!path) // there is no path given so we use the sftp_path
      pstr = sftppath;
   else if (path[0] == '/') // absolute path, take it
      pstr = path;
   else // relative path
      pstr = sftppath + "/" + path;

   BlockingHelper bh(this);

   LIBSSH2_SFTP_HANDLE* dh;
   do {
      dh = libssh2_sftp_opendir(sftp_session, pstr.c_str());  
      if (!dh) {
         if (libssh2_session_last_errno(ssh_session) == LIBSSH2_ERROR_EAGAIN) {
            if (waitsocket_unlocked(xsink, SFTPCLIENT_TIMEOUT, "SFTPCLIENT-LIST-ERROR", "SFTPClient::list", timeout_ms))
               return 0;
         }
         else {
            xsink->raiseException("SFTPCLIENT-LIST-ERROR", "cannot open '%s' as directory", pstr.c_str());
            return 0;
         }
      }
   } while (!dh);

   ON_BLOCK_EXIT(libssh2_sftp_close_handle, dh);

   // create objects after only possible error
   ReferenceHolder<QoreListNode> files(new QoreListNode, xsink);
   ReferenceHolder<QoreListNode> dirs(new QoreListNode, xsink);
   ReferenceHolder<QoreListNode> links(new QoreListNode, xsink);

   char buff[PATH_MAX];
   LIBSSH2_SFTP_ATTRIBUTES attrs;

   while (true) {
      int rc;
      while ((rc = libssh2_sftp_readdir(dh, buff, sizeof(buff), &attrs)) == LIBSSH2_ERROR_EAGAIN) {
         if (waitsocket_unlocked(xsink, SFTPCLIENT_TIMEOUT, "SFTPCLIENT-LIST-ERROR", "SFTPClient::list", timeout_ms))
            return 0;
      }
      if (!rc)
         break;
      if (rc < 0) {
         do_session_err_unlocked(xsink, "error reading directory '%s'", pstr.c_str());
         return 0;
      }
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

   QoreHashNode* ret = new QoreHashNode;

   ret->setKeyValue("path", new QoreStringNode(pstr.c_str()), xsink);
   // QoreListNode::sort() returns a new QoreListNode object
   ret->setKeyValue("directories", dirs->sort(), xsink);
   ret->setKeyValue("files", files->sort(), xsink);
   ret->setKeyValue("links", links->sort(), xsink);

   return ret;
}

// return 0 if ok, -1 otherwise
int SFTPClient::sftp_chmod(const char* file, const int mode, int timeout_ms, ExceptionSink* xsink) {
   static const char* SFTPCLIENT_CHMOD_ERROR = "SFTPCLIENT-CHMOD-ERROR";

   assert(file);

   if (!file || !file[0]) {
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
      pstr = sftppath + "/" + std::string(file);

   BlockingHelper bh(this);

   // try to get stats for this file
   LIBSSH2_SFTP_ATTRIBUTES attrs;

   int rc;
   while ((rc = libssh2_sftp_stat(sftp_session, pstr.c_str(), &attrs)) == LIBSSH2_ERROR_EAGAIN) {
      if (waitsocket_unlocked(xsink, SFTPCLIENT_TIMEOUT, SFTPCLIENT_CHMOD_ERROR, "SFTPClient::chmod", timeout_ms))
         return -3;
   }

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
   while ((rc = libssh2_sftp_setstat(sftp_session, pstr.c_str(), &attrs)) == LIBSSH2_ERROR_EAGAIN) {
      if (waitsocket_unlocked(xsink, SFTPCLIENT_TIMEOUT, SFTPCLIENT_CHMOD_ERROR, "SFTPClient::chmod", timeout_ms))
         return -3;
   }

   if (rc < 0) {
      // re-read the attributes
      while ((rc = libssh2_sftp_stat(sftp_session, pstr.c_str(), &attrs)) == LIBSSH2_ERROR_EAGAIN) {
         if (waitsocket_unlocked(xsink, SFTPCLIENT_TIMEOUT, SFTPCLIENT_CHMOD_ERROR, "SFTPClient::chmod", timeout_ms))
            return -3;
      }

      // they are how they should be, so we are done
      if (rc >= 0 && attrs.permissions == newmode)
         return 0;

      // ok, there was a error
      do_session_err_unlocked(xsink, "SFTPClient::chmod() raised an error in libssh2_sftp_setstat(%s)", pstr.c_str());
   }

   return rc;
}

// return 0 if ok, -1 otherwise
int SFTPClient::sftp_mkdir(const char* dir, const int mode, int timeout_ms, ExceptionSink* xsink) {
   assert(dir);

   if (!dir || !dir[0]) {
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
      pstr = sftppath + "/" + std::string(dir);

   BlockingHelper bh(this);

   // TODO: use proper modes for created dir
   int rc;
   while ((rc = libssh2_sftp_mkdir(sftp_session, pstr.c_str(), mode)) == LIBSSH2_ERROR_EAGAIN) {
      if (waitsocket_unlocked(xsink, SFTPCLIENT_TIMEOUT, "SFTPCLIENT-MKDIR-ERROR", "SFTPClient::mkdir", timeout_ms))
         return -3;
   }

   if (rc < 0)
      do_session_err_unlocked(xsink, "SFTPClient::mkdir() raised an error in libssh2_sftp_mkdir(%s)", pstr.c_str());

   return rc;
}

int SFTPClient::sftp_rmdir(const char* dir, int timeout_ms, ExceptionSink* xsink) {
   assert(dir);

   if (!dir || !dir[0]) {
      xsink->raiseException("SFTPCLIENT-RMDIR-ERROR", "directory name is empty");
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
      pstr = sftppath + "/" + std::string(dir);

   BlockingHelper bh(this);

   int rc;
   while ((rc = libssh2_sftp_rmdir(sftp_session, pstr.c_str())) == LIBSSH2_ERROR_EAGAIN) {
      if (waitsocket_unlocked(xsink, SFTPCLIENT_TIMEOUT, "SFTPCLIENT-RMDIR-ERROR", "SFTPClient::rmdir", timeout_ms))
         return -3;
   }
   if (rc < 0)
      do_session_err_unlocked(xsink, "SFTPClient::rmdir() raised an error in libssh2_sftp_rmdir(%s)", pstr.c_str());

   return rc;
}

int SFTPClient::sftp_rename(const char* from, const char* to, int timeout_ms, ExceptionSink* xsink) {
   assert(from && to);

   AutoLocker al(m);

   // no path?
   if (!sftp_connected_unlocked()) {
      xsink->raiseException(SFTPCLIENT_NOT_CONNECTED, "not connected");
      return -2;
   }

   std::string fstr, tstr;
   fstr = absolute_filename(this, from);
   tstr = absolute_filename(this, to);

   BlockingHelper bh(this);

   int rc;
   while ((rc = libssh2_sftp_rename(sftp_session, fstr.c_str(), tstr.c_str())) == LIBSSH2_ERROR_EAGAIN) {
      if (waitsocket_unlocked(xsink, SFTPCLIENT_TIMEOUT, "SFTPCLIENT-RENAME-ERROR", "SFTPClient::rename", timeout_ms))
         return -3;
   }
   if (rc < 0)
      do_session_err_unlocked(xsink, "SFTPClient::rename() raised an error in libssh2_sftp_rename(%s, %s)", fstr.c_str(), tstr.c_str());

   return rc;
}

int SFTPClient::sftp_unlink(const char* file, int timeout_ms, ExceptionSink* xsink) {
   assert(file);

   AutoLocker al(m);

   // no path?
   if (!sftp_connected_unlocked()) {
      xsink->raiseException(SFTPCLIENT_NOT_CONNECTED, "not connected");
      return -2;
   }

   std::string fstr;
   if (file[0] == '/')
      fstr = std::string(file);
   else
      fstr = sftppath + "/" + std::string(file);

   BlockingHelper bh(this);

   int rc;
   while ((rc = libssh2_sftp_unlink(sftp_session, fstr.c_str())) == LIBSSH2_ERROR_EAGAIN) {
      if (waitsocket_unlocked(xsink, SFTPCLIENT_TIMEOUT, "SFTPCLIENT-REMOVEFILE-ERROR", "SFTPClient::removeFile", timeout_ms))
         return -3;
   }

   if (rc < 0)
      do_session_err_unlocked(xsink, "SFTPClient::removeFile() raised an error in libssh2_sftp_unlink(%s)", fstr.c_str());

   return rc;
}

QoreStringNode* SFTPClient::sftp_chdir(const char* nwd, int timeout_ms, ExceptionSink* xsink) {
   char buff[PATH_MAX];
   *buff='\0';

   AutoLocker al(m);

   // no path?
   if (!sftp_connected_unlocked()) {
      xsink->raiseException(SFTPCLIENT_NOT_CONNECTED, "not connected");
      return 0;
   }

   // calc the path. if it starts with '/', replace with nwd
   std::string npath;
   if (!nwd)
      npath = sftppath;
   else if(nwd[0] == '/')
      npath = std::string(nwd);
   else
      npath = sftppath + "/" + std::string(nwd);

   BlockingHelper bh(this);

   // returns the amount of chars
   int rc;
   while ((rc = libssh2_sftp_realpath(sftp_session, npath.c_str(), buff, sizeof(buff)-1)) == LIBSSH2_ERROR_EAGAIN) {
      if (waitsocket_unlocked(xsink, SFTPCLIENT_TIMEOUT, "SFTPCLIENT-CHDIR-ERROR", "SFTPClient::chdir", timeout_ms))
         return 0;
   }
   if (rc < 0) {
      do_session_err_unlocked(xsink, "SFTPClient::chdir() raised an error while retrieving the remote path for: '%s'", npath.c_str());
      return 0;
   }

   // check if it is a directory
   LIBSSH2_SFTP_HANDLE* dh;
   do {
      dh = libssh2_sftp_opendir(sftp_session, buff);
      if (!dh) {
         if (libssh2_session_last_errno(ssh_session) == LIBSSH2_ERROR_EAGAIN) {
            if (waitsocket_unlocked(xsink, SFTPCLIENT_TIMEOUT, "SFTPCLIENT-CHDIR-ERROR", "SFTPClient::chdir", timeout_ms))
               return 0;
         }
         else {
            xsink->raiseException("SFTPCLIENT-CHDIR-ERROR", "'%s' is not a directory", buff);
            return 0;
         }
      }
   } while (!dh);

   libssh2_sftp_closedir(dh);

   // save new path
   sftppath = buff;

   return new QoreStringNode(sftppath);
}

QoreStringNode* SFTPClient::sftp_path_unlocked() {
   return sftppath.empty() ? 0 : new QoreStringNode(sftppath);
}

QoreStringNode* SFTPClient::sftp_path() {
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
int SFTPClient::sftp_connect_unlocked(int timeout_ms, ExceptionSink* xsink) {
   if (sftp_session)
      sftp_disconnect_unlocked(true);

   int rc;

   rc = ssh_connect_unlocked(timeout_ms, xsink);
   if (rc)
      return rc;

   QORE_TRACE("SFTPClient::connect()");

   BlockingHelper bh(this);

   do {
      // init sftp session
      sftp_session = libssh2_sftp_init(ssh_session);
  
      if (!sftp_session) {
         if (libssh2_session_last_errno(ssh_session) == LIBSSH2_ERROR_EAGAIN) {
            if (waitsocket_unlocked(xsink, SFTPCLIENT_TIMEOUT, SFTPCLIENT_CONNECT_ERROR, "SFTPClient::connect", timeout_ms))
               return -1;
         }
         else {
            sftp_disconnect_unlocked(true); // force shutdown
            xsink && xsink->raiseException(SFTPCLIENT_CONNECT_ERROR, "Unable to init SFTP session");
            return -1;
         }
      }
   } while (!sftp_session);
  
   // get the cwd for the path
   char buff[PATH_MAX];
   // returns the amount of chars
   while ((rc = libssh2_sftp_realpath(sftp_session, ".", buff, sizeof(buff) - 1)) == LIBSSH2_ERROR_EAGAIN) {
      if (waitsocket_unlocked(xsink, SFTPCLIENT_TIMEOUT, SFTPCLIENT_CONNECT_ERROR, "SFTPClient::connect", timeout_ms))
         return -1;
   }
   if (rc <= 0) {
      if (xsink)
         do_session_err_unlocked(xsink, "SFTPClient::connect() raised an error in libssh2_sftp_realpath()");
      sftp_disconnect_unlocked(true); // force shutdown
      return -1;
   }
   // for safety: do end string
   buff[rc] = '\0';
   sftppath = buff;
  
   return 0;
}

int SFTPClient::sftp_connect(int timeout_ms, ExceptionSink* xsink) {
   AutoLocker al(m);

   return sftp_connect_unlocked(timeout_ms, xsink);
}

BinaryNode *SFTPClient::sftp_getFile(const char* file, int timeout_ms, ExceptionSink* xsink) {
   AutoLocker al(m);

   if (!sftp_connected_unlocked()) {
      xsink->raiseException(SFTPCLIENT_NOT_CONNECTED, "not connected");
      return NULL;
   }

   std::string fname = absolute_filename(this, file);

   BlockingHelper bh(this);

   LIBSSH2_SFTP_ATTRIBUTES attrs;
   int rc;
   while ((rc = libssh2_sftp_stat(sftp_session, fname.c_str(), &attrs)) == LIBSSH2_ERROR_EAGAIN) {
      if (waitsocket_unlocked(xsink, SFTPCLIENT_TIMEOUT, "SFTPCLIENT-GETFILE-ERROR", "SFTPClient::getFile", timeout_ms))
         return 0;
   }
   if (rc < 0) {
      do_session_err_unlocked(xsink, "SFTPClient::getFile() raised an error in libssh2_sftp_stat(%s)", fname.c_str());
      return 0;
   }
   //printd(0, "SFTPClient::sftp_getFile() permissions: %lo\n", attrs.permissions);
   size_t fsize = attrs.filesize;

   // open handle
   LIBSSH2_SFTP_HANDLE* sftp_handle;
   do {
      sftp_handle = libssh2_sftp_open(sftp_session, fname.c_str(), LIBSSH2_FXF_READ, attrs.permissions);
      if (!sftp_handle) {
         if (libssh2_session_last_errno(ssh_session) == LIBSSH2_ERROR_EAGAIN) {
            if (waitsocket_unlocked(xsink, SFTPCLIENT_TIMEOUT, "SFTPCLIENT-GETFILE-ERROR", "SFTPClient::getFile", timeout_ms))
               return 0;
         }
         else {
            do_session_err_unlocked(xsink, "SFTPClient::getFile() raised an error in libssh2_sftp_open(%s)", fname.c_str());
            return 0;
         }
      }
   } while (!sftp_handle);

   // close file
   // errors can be ignored, because by the time we close, we should have already what we want
   ON_BLOCK_EXIT(libssh2_sftp_close_handle, sftp_handle);

   // create binary node for return with the size the server gave us on stat
   SimpleRefHolder<BinaryNode> bn(new BinaryNode());
   bn->preallocate(fsize);

   size_t tot = 0;
   while (true) {
      while ((rc = libssh2_sftp_read(sftp_handle, (char*)bn->getPtr() + tot, fsize - tot)) == LIBSSH2_ERROR_EAGAIN) {
         if (waitsocket_unlocked(xsink, SFTPCLIENT_TIMEOUT, "SFTPCLIENT-GETFILE-ERROR", "SFTPClient::getFile", timeout_ms))
            return 0;
      }
      if (rc < 0) {
         do_session_err_unlocked(xsink, "SFTPClient::getFile() raised an error in libssh2_sftp_read(%ld) total read: %ld while reading '%s' size %ld", fsize - tot, tot, fname.c_str(), fsize);
         return 0;
      }
      if (rc)
         tot += rc;
      if (tot >= fsize)
         break;
   }
   bn->setSize(tot);

   return bn.release();
}

QoreStringNode *SFTPClient::sftp_getTextFile(const char* file, int timeout_ms, const QoreEncoding *encoding, ExceptionSink* xsink) {
   AutoLocker al(m);

   if (!sftp_connected_unlocked()) {
      xsink->raiseException(SFTPCLIENT_NOT_CONNECTED, "This action can only be performed if the client is connected");
      return NULL;
   }

   std::string fname = absolute_filename(this, file);

   BlockingHelper bh(this);

   LIBSSH2_SFTP_ATTRIBUTES attrs;
   int rc;
   while ((rc = libssh2_sftp_stat(sftp_session, fname.c_str(), &attrs)) == LIBSSH2_ERROR_EAGAIN) {
      if (waitsocket_unlocked(xsink, SFTPCLIENT_TIMEOUT, "SFTPCLIENT-GETTEXTFILE-ERROR", "SFTPClient::getTextFile", timeout_ms))
         return 0;
   }
   if (rc < 0) {
      do_session_err_unlocked(xsink, "SFTPClient::getTextFile() raised an error in libssh2_sftp_stat(%s)", fname.c_str());
      return 0;
   }
   size_t fsize = attrs.filesize;
   
   // open handle
   LIBSSH2_SFTP_HANDLE* sftp_handle;
   do {
      sftp_handle = libssh2_sftp_open(sftp_session, fname.c_str(), LIBSSH2_FXF_READ, attrs.permissions);
      if (!sftp_handle) {
         if (libssh2_session_last_errno(ssh_session) == LIBSSH2_ERROR_EAGAIN) {
            if (waitsocket_unlocked(xsink, SFTPCLIENT_TIMEOUT, "SFTPCLIENT-GETTEXTFILE-ERROR", "SFTPClient::getTextFile", timeout_ms))
               return 0;
         }
         else {
            do_session_err_unlocked(xsink, "SFTPClient::getTextFile() raised an error in libssh2_sftp_open(%s)", fname.c_str());
            return 0;
         }
      }
   } while (!sftp_handle);

   // close file
   // errors can be ignored, because by the time we close, we should already have what we want
   ON_BLOCK_EXIT(libssh2_sftp_close_handle, sftp_handle);

   // create buffer for return with the size the server gave us on stat + 1 byte for termination char
   SimpleRefHolder<QoreStringNode> str(new QoreStringNode(encoding));
   str->allocate(fsize + 1);
   
   size_t tot = 0;
   while (true) {
      while ((rc = libssh2_sftp_read(sftp_handle, (char*)str->getBuffer() + tot, fsize - tot)) == LIBSSH2_ERROR_EAGAIN) {
         if (waitsocket_unlocked(xsink, SFTPCLIENT_TIMEOUT, "SFTPCLIENT-GETTEXTFILE-ERROR", "SFTPClient::getTextFile", timeout_ms))
            return 0;
      }
      if (rc < 0) {
         do_session_err_unlocked(xsink, "SFTPClient::getTextFile() raised an error in libssh2_sftp_read(%ld) total read: %ld while reading '%s' size %ld", fsize - tot, tot, fname.c_str(), fsize);
         return 0;
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
qore_size_t SFTPClient::sftp_putFile(const char* outb, qore_size_t towrite, const char* fname, int mode, int timeout_ms, ExceptionSink* xsink) {
   AutoLocker al(m);

   if (!sftp_connected_unlocked()) {
      xsink->raiseException(SFTPCLIENT_NOT_CONNECTED, "This action can only be performed if the client is connected");
      return -1;
   }

   std::string file = absolute_filename(this, fname);

   BlockingHelper bh(this);

   // if this works we try to open an sftp handle on the other side
   LIBSSH2_SFTP_HANDLE* sftp_handle;
   do {
      sftp_handle = libssh2_sftp_open_ex(sftp_session, file.c_str(), file.size(), LIBSSH2_FXF_WRITE|LIBSSH2_FXF_CREAT|LIBSSH2_FXF_TRUNC, mode, LIBSSH2_SFTP_OPENFILE);
      if (!sftp_handle) {
         if (libssh2_session_last_errno(ssh_session) == LIBSSH2_ERROR_EAGAIN) {
            if (waitsocket_unlocked(xsink, SFTPCLIENT_TIMEOUT, "SFTPCLIENT-PUTFILE-ERROR", "SFTPClient::putFile", timeout_ms))
               return -1;
         }
         else {
            do_session_err_unlocked(xsink, "SFTPClient::putFile() raised an error in libssh2_sftp_open_ex(%s)", file.c_str());
            return -1;
         }
      }
   } while (!sftp_handle);

   qore_size_t size = 0;
   while (size < towrite) {
      ssize_t rc;
      while ((rc = libssh2_sftp_write(sftp_handle, outb, towrite - size)) == LIBSSH2_ERROR_EAGAIN) {
         if (waitsocket_unlocked(xsink, SFTPCLIENT_TIMEOUT, "SFTPCLIENT-PUTFILE-ERROR", "SFTPClient::putFile", timeout_ms)) {
            // note: memory leak here! we cannot close the handle due to the timeout
            return -1;
         }
      }
      if (rc < 0) { 
         do_session_err_unlocked(xsink, "SFTPClient::putFile() raised an error in libssh2_sftp_open_ex(%ld) while writing '%s', total written: %ld, total to write: %ld", towrite - size, file.c_str(), size, towrite);
         // close the handle
         int rc;
         while ((rc = libssh2_sftp_close(sftp_handle)) == LIBSSH2_ERROR_EAGAIN) {
            if (waitsocket_unlocked(xsink, SFTPCLIENT_TIMEOUT, "SFTPCLIENT-PUTFILE-ERROR", "SFTPClient::putFile", timeout_ms)) {
               // note: memory leak here! we cannot close the handle due to the timeout
               return -1;
            }
         }

         return -1;
      }
      size += rc;
   }

   // will return 0 on sucess
   // we check this error, because we want to be sure the file was written
   int rc;
   while ((rc = libssh2_sftp_close(sftp_handle)) == LIBSSH2_ERROR_EAGAIN) {
      if (waitsocket_unlocked(xsink, SFTPCLIENT_TIMEOUT, "SFTPCLIENT-PUTFILE-ERROR", "SFTPClient::putFile", timeout_ms)) {
         // note: memory leak here! we cannot close the handle due to the timeout
         return -1;
      }
   }
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
int SFTPClient::sftp_getAttributes(const char* fname, LIBSSH2_SFTP_ATTRIBUTES *attrs, int timeout_ms, ExceptionSink* xsink) {
   assert(fname);

   AutoLocker al(m);

   if (!sftp_connected_unlocked()) {
      xsink->raiseException(SFTPCLIENT_NOT_CONNECTED, "This action can only be performed if the client is connected");
      return -3;
   }

   if (!fname || !fname[0]) {
      xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "no file given");
      return -2;
   }

   std::string file = absolute_filename(this, fname);

   BlockingHelper bh(this);
 
   // stat the file
   int rc;
   while ((rc = libssh2_sftp_stat(sftp_session, file.c_str(), attrs)) == LIBSSH2_ERROR_EAGAIN) {
      if (waitsocket_unlocked(xsink, SFTPCLIENT_TIMEOUT, "SFTPCLIENT-STAT-ERROR", "SFTPClient::stat", timeout_ms))
         return -3;
   }

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

void SFTPClient::do_session_err_unlocked(ExceptionSink* xsink, const char* fmt, ...) {
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

      desc->sprintf(": sftp error code %lu", serr);

      edmap_t::const_iterator i = sftp_emap.find((int)serr);
      if (i != sftp_emap.end())
         desc->sprintf(" (%s): %s", i->second.err, i->second.desc);
      else
         desc->concat(": unknown sftp error code");
   }
   else
      desc->sprintf(": ssh2 error %d: %s", err, get_session_err_unlocked());

   xsink->raiseException(SSH2_ERROR, desc);
}

QoreHashNode *SFTPClient::sftp_info() {
   AutoLocker al(m);
   QoreHashNode *h = ssh_info_intern();
   h->setKeyValue("path", sftppath.empty() ? 0 : new QoreStringNode(sftppath), 0);
   return h;
}
