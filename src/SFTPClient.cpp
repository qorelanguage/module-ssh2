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
#include <sys/stat.h>
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#include <assert.h>
#include <unistd.h>

static const char* SFTPCLIENT_CONNECT_ERROR = "SFTPCLIENT-CONNECT-ERROR";
static const char* SFTPCLIENT_TIMEOUT = "SFTPCLIENT-TIMEOUT";

static const char* ssh2_mode_to_perm(mode_t mode, QoreString& perm) {
   const char* type;
   if (S_ISBLK(mode)) {
      type = "BLOCK-DEVICE";
      perm.concat('b');
   }
   else if (S_ISDIR(mode)) {
      type = "DIRECTORY";
      perm.concat('d');
   }
   else if (S_ISCHR(mode)) {
      type = "CHARACTER-DEVICE";
      perm.concat('c');
   }
   else if (S_ISFIFO(mode)) {
      type = "FIFO";
      perm.concat('p');
   }
#ifdef S_ISLNK
   else if (S_ISLNK(mode)) {
      type = "SYMBOLIC-LINK";
      perm.concat('l');
   }
#endif
#ifdef S_ISSOCK
   else if (S_ISSOCK(mode)) {
      type = "SOCKET";
      perm.concat('s');
   }
#endif
   else if (S_ISREG(mode)) {
      type = "REGULAR";
      perm.concat('-');
   }
   else {
      type = "UNKNOWN";
      perm.concat('?');
   }

   // add user permission flags
   perm.concat(mode & S_IRUSR ? 'r' : '-');
   perm.concat(mode & S_IWUSR ? 'w' : '-');
#ifdef S_ISUID
   if (mode & S_ISUID)
      perm.concat(mode & S_IXUSR ? 's' : 'S');
   else
      perm.concat(mode & S_IXUSR ? 'x' : '-');
#else
   // Windows
   perm.concat('-');
#endif

   // add group permission flags
#ifdef S_IRGRP
   perm.concat(mode & S_IRGRP ? 'r' : '-');
   perm.concat(mode & S_IWGRP ? 'w' : '-');
#else
   // Windows
   perm.concat("--");
#endif
#ifdef S_ISGID
   if (mode & S_ISGID)
      perm.concat(mode & S_IXGRP ? 's' : 'S');
   else
      perm.concat(mode & S_IXGRP ? 'x' : '-');
#else
   // Windows
   perm.concat('-');
#endif

#ifdef S_IROTH
   // add other permission flags
   perm.concat(mode & S_IROTH ? 'r' : '-');
   perm.concat(mode & S_IWOTH ? 'w' : '-');
   if (mode & S_ISVTX)
      perm.concat(mode & S_IXOTH ? 't' : 'T');
   else
      perm.concat(mode & S_IXOTH ? 'x' : '-');
#else
   // Windows
   perm.concat("---");
#endif

   return type;
}

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

   // try to make an implicit connection
   if (!sftp_connected_unlocked() && sftp_connect_unlocked(timeout_ms, xsink))
      return 0;

   std::string pstr;
   if (!path) // there is no path given so we use the sftp_path
      pstr = sftppath;
   else if (path[0] == '/') // absolute path, take it
      pstr = path;
   else // relative path
      pstr = sftppath + "/" + path;

   BlockingHelper bh(this);

   QSftpHelper qh(this, "SFTPCLIENT-LIST-ERROR", "SFTPClient::list", timeout_ms, xsink);

   do {
      qh.assign(libssh2_sftp_opendir(sftp_session, pstr.c_str()));
      if (!qh) {
         if (libssh2_session_last_errno(ssh_session) == LIBSSH2_ERROR_EAGAIN) {
            if (qh.waitSocket())
               return 0;
         }
         else {
            qh.err("error reading directory '%s'", pstr.c_str());
            return 0;
         }
      }
   } while (!qh);

   // create objects after only possible error
   ReferenceHolder<QoreListNode> files(new QoreListNode, xsink);
   ReferenceHolder<QoreListNode> dirs(new QoreListNode, xsink);
   ReferenceHolder<QoreListNode> links(new QoreListNode, xsink);

   char buff[PATH_MAX];
   LIBSSH2_SFTP_ATTRIBUTES attrs;

   while (true) {
      int rc;
      while ((rc = libssh2_sftp_readdir(*qh, buff, sizeof(buff), &attrs)) == LIBSSH2_ERROR_EAGAIN) {
         if (qh.waitSocket())
            return 0;
      }
      if (!rc)
         break;
      if (rc < 0) {
         qh.err("error reading directory '%s'", pstr.c_str());
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

QoreListNode *SFTPClient::sftp_list_full(const char* path, int timeout_ms, ExceptionSink* xsink) {
   AutoLocker al(m);

   // try to make an implicit connection
   if (!sftp_connected_unlocked() && sftp_connect_unlocked(timeout_ms, xsink))
      return 0;

   std::string pstr;
   if (!path) // there is no path given so we use the sftp_path
      pstr = sftppath;
   else if (path[0] == '/') // absolute path, take it
      pstr = path;
   else // relative path
      pstr = sftppath + "/" + path;

   BlockingHelper bh(this);

   QSftpHelper qh(this, "SFTPCLIENT-LISTFULL-ERROR", "SFTPClient::listFull", timeout_ms, xsink);

   do {
      qh.assign(libssh2_sftp_opendir(sftp_session, pstr.c_str()));
      if (!qh) {
         if (libssh2_session_last_errno(ssh_session) == LIBSSH2_ERROR_EAGAIN) {
            if (qh.waitSocket())
               return 0;
         }
         else {
            qh.err("error reading directory '%s'", pstr.c_str());
            return 0;
         }
      }
   } while (!qh);

   // create objects after only possible error
   ReferenceHolder<QoreListNode> rv(new QoreListNode, xsink);

   char buff[PATH_MAX];
   LIBSSH2_SFTP_ATTRIBUTES attrs;

   while (true) {
      int rc;
      while ((rc = libssh2_sftp_readdir(*qh, buff, sizeof(buff), &attrs)) == LIBSSH2_ERROR_EAGAIN) {
         if (qh.waitSocket())
            return 0;
      }
      if (!rc)
         break;
      if (rc < 0) {
         qh.err("error reading directory '%s'", pstr.c_str());
         return 0;
      }

      QoreHashNode* h = new QoreHashNode;
      h->setKeyValue("name", new QoreStringNode(buff), 0);

      if (attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) {
         QoreStringNode* perm = new QoreStringNode;
         const char* type = ssh2_mode_to_perm(attrs.permissions, *perm);

         h->setKeyValue("size", new QoreBigIntNode(attrs.filesize), 0);
         h->setKeyValue("atime", DateTimeNode::makeAbsolute(currentTZ(), (int64)attrs.atime), 0);
         h->setKeyValue("mtime", DateTimeNode::makeAbsolute(currentTZ(), (int64)attrs.mtime), 0);
         h->setKeyValue("uid", new QoreBigIntNode(attrs.uid), 0);
         h->setKeyValue("gid", new QoreBigIntNode(attrs.gid), 0);
         h->setKeyValue("mode", new QoreBigIntNode(attrs.permissions), 0);
         h->setKeyValue("type", new QoreStringNode(type), 0);
         h->setKeyValue("perm", perm, 0);
      }

      rv->push(h);
   }

   return rv.release();
}

// return 0 if ok, -1 otherwise
int SFTPClient::sftp_chmod(const char* file, const int mode, int timeout_ms, ExceptionSink* xsink) {
   static const char* SFTPCLIENT_CHMOD_ERROR = "SFTPCLIENT-CHMOD-ERROR";

   assert(file);

   QSftpHelper qh(this, SFTPCLIENT_CHMOD_ERROR, "SFTPClient::chmod", timeout_ms, xsink);

   if (!file || !file[0]) {
      qh.err("file argument is empty");
      return -3;
   }

   AutoLocker al(m);

   // try to make an implicit connection
   if (!sftp_connected_unlocked() && sftp_connect_unlocked(timeout_ms, xsink))
      return -2;

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
      if (qh.waitSocket())
         return -3;
   }

   if (rc < 0) {
      qh.err("libssh2_sftp_stat(%s) returned an error", pstr.c_str());
      return rc;
   }

   // overwrite permissions
   if (!(attrs.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS)) {
      qh.err("permissions not supported by sftp server");
      return -3;
   }

   // set the permissions for file only (ugo)
   unsigned long newmode = (attrs.permissions & (-1^SFTP_UGOMASK)) | (mode & SFTP_UGOMASK);
   attrs.permissions = newmode;

   // set the permissions (stat). it happens that we get a 'SFTP Protocol Error' so we check manually
   while ((rc = libssh2_sftp_setstat(sftp_session, pstr.c_str(), &attrs)) == LIBSSH2_ERROR_EAGAIN) {
      if (qh.waitSocket())
         return -3;
   }

   if (rc < 0) {
      // re-read the attributes
      while ((rc = libssh2_sftp_stat(sftp_session, pstr.c_str(), &attrs)) == LIBSSH2_ERROR_EAGAIN) {
         if (qh.waitSocket())
            return -3;
      }

      // they are how they should be, so we are done
      if (rc >= 0 && attrs.permissions == newmode)
         return 0;

      // ok, there was a error
      qh.err("libssh2_sftp_setstat(%s) returned an error", pstr.c_str());
   }

   return rc;
}

// return 0 if ok, -1 otherwise
int SFTPClient::sftp_mkdir(const char* dir, const int mode, int timeout_ms, ExceptionSink* xsink) {
   assert(dir);

   QSftpHelper qh(this, "SFTPCLIENT-MKDIR-ERROR", "SFTPClient::mkdir", timeout_ms, xsink);

   if (!dir || !dir[0]) {
      qh.err("directory name is empty");
      return -3;
   }

   AutoLocker al(m);

   // try to make an implicit connection
   if (!sftp_connected_unlocked() && sftp_connect_unlocked(timeout_ms, xsink))
      return -2;

   std::string pstr;
   if (dir[0] == '/')
      pstr = std::string(dir);
   else
      pstr = sftppath + "/" + std::string(dir);

   BlockingHelper bh(this);

   // TODO: use proper modes for created dir
   int rc;
   while ((rc = libssh2_sftp_mkdir(sftp_session, pstr.c_str(), mode)) == LIBSSH2_ERROR_EAGAIN) {
      if (qh.waitSocket())
         return -3;
   }

   if (rc < 0)
      qh.err("libssh2_sftp_mkdir(%s) returned an error", pstr.c_str());

   return rc;
}

int SFTPClient::sftp_rmdir(const char* dir, int timeout_ms, ExceptionSink* xsink) {
   assert(dir);

   QSftpHelper qh(this, "SFTPCLIENT-RMDIR-ERROR", "SFTPClient::rmdir", timeout_ms, xsink);

   if (!dir || !dir[0]) {
      qh.err("directory name is empty");
      return -3;
   }

   AutoLocker al(m);

   // try to make an implicit connection
   if (!sftp_connected_unlocked() && sftp_connect_unlocked(timeout_ms, xsink))
      return -2;

   std::string pstr;
   if (dir[0] == '/')
      pstr = std::string(dir);
   else
      pstr = sftppath + "/" + std::string(dir);

   BlockingHelper bh(this);

   int rc;
   while ((rc = libssh2_sftp_rmdir(sftp_session, pstr.c_str())) == LIBSSH2_ERROR_EAGAIN) {
      if (qh.waitSocket())
         return -3;
   }
   if (rc < 0)
      qh.err("libssh2_sftp_rmdir(%s) returned an error", pstr.c_str());

   return rc;
}

int SFTPClient::sftp_rename(const char* from, const char* to, int timeout_ms, ExceptionSink* xsink) {
   assert(from && to);

   QSftpHelper qh(this, "SFTPCLIENT-RENAME-ERROR", "SFTPClient::rename", timeout_ms, xsink);

   AutoLocker al(m);

   // try to make an implicit connection
   if (!sftp_connected_unlocked() && sftp_connect_unlocked(timeout_ms, xsink))
      return -2;

   std::string fstr, tstr;
   fstr = absolute_filename(this, from);
   tstr = absolute_filename(this, to);

   BlockingHelper bh(this);

   int rc;
   while ((rc = libssh2_sftp_rename(sftp_session, fstr.c_str(), tstr.c_str())) == LIBSSH2_ERROR_EAGAIN) {
      if (qh.waitSocket())
         return -3;
   }
   if (rc < 0)
      qh.err("libssh2_sftp_rename(%s, %s) returned an error", fstr.c_str(), tstr.c_str());

   return rc;
}

int SFTPClient::sftp_unlink(const char* file, int timeout_ms, ExceptionSink* xsink) {
   assert(file);

   QSftpHelper qh(this, "SFTPCLIENT-REMOVEFILE-ERROR", "SFTPClient::removeFile", timeout_ms, xsink);

   AutoLocker al(m);

   // try to make an implicit connection
   if (!sftp_connected_unlocked() && sftp_connect_unlocked(timeout_ms, xsink))
      return -2;

   std::string fstr;
   if (file[0] == '/')
      fstr = std::string(file);
   else
      fstr = sftppath + "/" + std::string(file);

   BlockingHelper bh(this);

   int rc;
   while ((rc = libssh2_sftp_unlink(sftp_session, fstr.c_str())) == LIBSSH2_ERROR_EAGAIN) {
      if (qh.waitSocket())
         return -3;
   }

   if (rc < 0)
      qh.err("libssh2_sftp_unlink(%s) returned an error", fstr.c_str());
   
   return rc;
}

QoreStringNode* SFTPClient::sftp_chdir(const char* nwd, int timeout_ms, ExceptionSink* xsink) {
   char buff[PATH_MAX];
   *buff='\0';

   QSftpHelper qh(this, "SFTPCLIENT-REMOVEFILE-ERROR", "SFTPClient::removeFile", timeout_ms, xsink);

   AutoLocker al(m);

   // try to make an implicit connection
   if (!sftp_connected_unlocked() && sftp_connect_unlocked(timeout_ms, xsink))
      return 0;

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
      if (qh.waitSocket())
         return 0;
   }
   if (rc < 0) {
      qh.err("failed to retrieve the remote path for: '%s'", npath.c_str());
      return 0;
   }

   // check if it is a directory
   do {
      qh.assign(libssh2_sftp_opendir(sftp_session, buff));
      if (!qh) {
         if (libssh2_session_last_errno(ssh_session) == LIBSSH2_ERROR_EAGAIN) {
            if (qh.waitSocket())
               return 0;
         }
         else {
            qh.err("'%s' is not a directory", buff);
            return 0;
         }
      }
   } while (!qh);

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

   QSftpHelper qh(this, SFTPCLIENT_CONNECT_ERROR, "SFTPClient::connect", timeout_ms, xsink);

   do {
      // init sftp session
      sftp_session = libssh2_sftp_init(ssh_session);
  
      if (!sftp_session) {
         if (libssh2_session_last_errno(ssh_session) == LIBSSH2_ERROR_EAGAIN) {
            if (qh.waitSocket())
               return -1;
         }
         else {
            sftp_disconnect_unlocked(true); // force shutdown
            if (xsink)
               qh.err("Unable to initialize SFTP session");
            return -1;
         }
      }
   } while (!sftp_session);
  
   if (sftppath.empty()) {
      // get the cwd for the path
      char buff[PATH_MAX];
      // returns the amount of chars
      while ((rc = libssh2_sftp_realpath(sftp_session, ".", buff, sizeof(buff) - 1)) == LIBSSH2_ERROR_EAGAIN) {
         if (qh.waitSocket())
            return -1;
      }
      if (rc <= 0) {
         if (xsink)
            qh.err("libssh2_sftp_realpath() returned an error");
         sftp_disconnect_unlocked(true); // force shutdown
         return -1;
      }
      // for safety: do end string
      buff[rc] = '\0';
      sftppath = buff;
   }

   return 0;
}

int SFTPClient::sftp_connect(int timeout_ms, ExceptionSink* xsink) {
   AutoLocker al(m);

   return sftp_connect_unlocked(timeout_ms, xsink);
}

BinaryNode *SFTPClient::sftp_getFile(const char* file, int timeout_ms, ExceptionSink* xsink) {
   AutoLocker al(m);

   // try to make an implicit connection
   if (!sftp_connected_unlocked() && sftp_connect_unlocked(timeout_ms, xsink))
      return 0;

   std::string fname = absolute_filename(this, file);

   BlockingHelper bh(this);

   QSftpHelper qh(this, "SFTPCLIENT-GETFILE-ERROR", "SFTPClient::getFile", timeout_ms, xsink);

   LIBSSH2_SFTP_ATTRIBUTES attrs;
   int rc;
   while ((rc = libssh2_sftp_stat(sftp_session, fname.c_str(), &attrs)) == LIBSSH2_ERROR_EAGAIN) {
      if (qh.waitSocket())
         return 0;
   }
   if (rc < 0) {
      qh.err("libssh2_sftp_stat(%s) returned an error", fname.c_str());
      return 0;
   }
   //printd(0, "SFTPClient::sftp_getFile() permissions: %lo\n", attrs.permissions);
   size_t fsize = attrs.filesize;

   // open handle
   do {
      qh.assign(libssh2_sftp_open(sftp_session, fname.c_str(), LIBSSH2_FXF_READ, attrs.permissions));
      if (!qh) {
         if (libssh2_session_last_errno(ssh_session) == LIBSSH2_ERROR_EAGAIN) {
            if (qh.waitSocket())
               return 0;
         }
         else {
            qh.err("libssh2_sftp_open(%s) returned an error", fname.c_str());
            return 0;
         }
      }
   } while (!qh);

   // close file
   // errors can be ignored, because by the time we close, we should have already what we want

   // create binary node for return with the size the server gave us on stat
   SimpleRefHolder<BinaryNode> bn(new BinaryNode());
   bn->preallocate(fsize);

   size_t tot = 0;
   while (true) {
      while ((rc = libssh2_sftp_read(*qh, (char*)bn->getPtr() + tot, fsize - tot)) == LIBSSH2_ERROR_EAGAIN) {
         if (qh.waitSocket())
            return 0;
      }
      if (rc < 0) {
         qh.err("libssh2_sftp_read(%ld) failed: total read: %ld while reading '%s' size %ld", fsize - tot, tot, fname.c_str(), fsize);
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

   // try to make an implicit connection
   if (!sftp_connected_unlocked() && sftp_connect_unlocked(timeout_ms, xsink))
      return 0;

   std::string fname = absolute_filename(this, file);

   BlockingHelper bh(this);

   QSftpHelper qh(this, "SFTPCLIENT-GETTEXTFILE-ERROR", "SFTPClient::getTextFile", timeout_ms, xsink);

   LIBSSH2_SFTP_ATTRIBUTES attrs;
   int rc;
   while ((rc = libssh2_sftp_stat(sftp_session, fname.c_str(), &attrs)) == LIBSSH2_ERROR_EAGAIN) {
      if (qh.waitSocket())
         return 0;
   }
   if (rc < 0) {
      qh.err("libssh2_sftp_stat(%s) returned an error", fname.c_str());
      return 0;
   }
   size_t fsize = attrs.filesize;
   
   // open handle
   do {
      qh.assign(libssh2_sftp_open(sftp_session, fname.c_str(), LIBSSH2_FXF_READ, attrs.permissions));
      if (!qh) {
         if (libssh2_session_last_errno(ssh_session) == LIBSSH2_ERROR_EAGAIN) {
            if (qh.waitSocket())
               return 0;
         }
         else {
            qh.err("libssh2_sftp_open(%s) returned an error", fname.c_str());
            return 0;
         }
      }
   } while (!qh);

   // close file
   // errors can be ignored, because by the time we close, we should already have what we want

   // create buffer for return with the size the server gave us on stat + 1 byte for termination char
   SimpleRefHolder<QoreStringNode> str(new QoreStringNode(encoding));
   str->allocate(fsize + 1);
   
   size_t tot = 0;
   while (true) {
      while ((rc = libssh2_sftp_read(*qh, (char*)str->getBuffer() + tot, fsize - tot)) == LIBSSH2_ERROR_EAGAIN) {
         if (qh.waitSocket())
            return 0;
      }
      if (rc < 0) {
         qh.err("libssh2_sftp_read(%ld) failed: total read: %ld while reading '%s' size %ld", fsize - tot, tot, fname.c_str(), fsize);
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

   // try to make an implicit connection
   if (!sftp_connected_unlocked() && sftp_connect_unlocked(timeout_ms, xsink))
      return -1;

   std::string file = absolute_filename(this, fname);

   BlockingHelper bh(this);

   QSftpHelper qh(this, "SFTPCLIENT-PUTFILE-ERROR", "SFTPClient::putFile", timeout_ms, xsink);

   // if this works we try to open an sftp handle on the other side
   do {
      qh.assign(libssh2_sftp_open_ex(sftp_session, file.c_str(), file.size(), LIBSSH2_FXF_WRITE|LIBSSH2_FXF_CREAT|LIBSSH2_FXF_TRUNC, mode, LIBSSH2_SFTP_OPENFILE));
      if (!qh) {
         if (libssh2_session_last_errno(ssh_session) == LIBSSH2_ERROR_EAGAIN) {
            if (qh.waitSocket())
               return -1;
         }
         else {
            qh.err("libssh2_sftp_open_ex(%s) returned an error", file.c_str());
            return -1;
         }
      }
   } while (!qh);
   
   qore_size_t size = 0;
   while (size < towrite) {
      ssize_t rc;
      while ((rc = libssh2_sftp_write(*qh, outb, towrite - size)) == LIBSSH2_ERROR_EAGAIN) {
         if (qh.waitSocket()) {
            // note: memory leak here! we cannot close the handle due to the timeout
            return -1;
         }
      }
      if (rc < 0) { 
         qh.err("libssh2_sftp_open_ex(%ld) failed while writing '%s', total written: %ld, total to write: %ld", towrite - size, file.c_str(), size, towrite);
         return -1;
      }
      size += rc;
   }

   int rc = qh.close();
   if (rc && rc != LIBSSH2_ERROR_EAGAIN) {
      qh.err("libssh2_sftp_close_handle() returned an error while closing '%s'", file.c_str());
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

   // try to make an implicit connection
   if (!sftp_connected_unlocked() && sftp_connect_unlocked(timeout_ms, xsink))
      return -3;

   QSftpHelper qh(this, "SFTPCLIENT-STAT-ERROR", "SFTPClient::stat", timeout_ms, xsink);

   if (!fname || !fname[0]) {
      qh.err("no file given");
      return -2;
   }

   std::string file = absolute_filename(this, fname);

   BlockingHelper bh(this);
 
   // stat the file
   int rc;
   while ((rc = libssh2_sftp_stat(sftp_session, file.c_str(), attrs)) == LIBSSH2_ERROR_EAGAIN) {
      if (qh.waitSocket())
         return -3;
   }

   if (rc < 0) {
      // check if the file does not exist
      if (libssh2_session_last_errno(ssh_session) == LIBSSH2_ERROR_SFTP_PROTOCOL
          && libssh2_sftp_last_error(sftp_session) == LIBSSH2_FX_NO_SUCH_FILE)
         return -2;

      qh.err("libssh2_sftp_stat(%s) returned an error", file.c_str());
      return -1;
   }

   return 0;
}

void SFTPClient::do_session_err_unlocked(ExceptionSink* xsink, QoreStringNode* desc) {
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

   // check if we're still connected: if there is data to be read, we assume it's the EOF marker and close the session
   int rc = waitsocket_select_unlocked(LIBSSH2_SESSION_BLOCK_INBOUND, 0);

   if (rc > 0) {
      printd(5, "do_session_err_unlocked() session %p: detected disconnected session, marking as closed\n", ssh_session);
      sftp_disconnect_unlocked(true, 10, xsink);
   }
}

void QSftpHelper::err(const char* fmt, ...) {
   tryClose();

   va_list args;
   QoreStringNode *desc = new QoreStringNode;

   while (true) {
      va_start(args, fmt);
      int rc = desc->vsprintf(fmt, args);
      va_end(args);
      if (!rc)
         break;
   }

   client->do_session_err_unlocked(xsink, desc);
}


QoreHashNode *SFTPClient::sftp_info() {
   AutoLocker al(m);
   QoreHashNode *h = ssh_info_intern();
   h->setKeyValue("path", sftppath.empty() ? 0 : new QoreStringNode(sftppath), 0);
   return h;
}

int QSftpHelper::closeIntern() {
   assert(sftp_handle);

   // close the handle
   int rc;
   while ((rc = libssh2_sftp_close_handle(sftp_handle)) == LIBSSH2_ERROR_EAGAIN) {
      if (client->waitsocket_unlocked(xsink, SFTPCLIENT_TIMEOUT, errstr, meth, timeout_ms)) {
         // note: memory leak here! we cannot close the handle due to the timeout
         break;
      }
   }

   return rc;
}

int QSftpHelper::waitSocket() {
   if (client->waitsocket_unlocked(xsink, SFTPCLIENT_TIMEOUT, errstr, meth, timeout_ms))
      return -1;
   return 0;
}
