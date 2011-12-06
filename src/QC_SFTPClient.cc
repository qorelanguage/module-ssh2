/* -*- indent-tabs-mode: nil -*- */
/*
  SFTPClient.h

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

//! @file SFTPClient.qc defines the SFTPClient class

#include "SFTPClient.h"

qore_classid_t CID_SFTP_CLIENT;

//! namespace for the SSH2 module
/**# namespace SSH2 {
*/
//! allows Qore programs to establish an ssh2 connection to a remote server
/** 
 */
/**# class SFTPClient inherits SSH2Base {
public:
 */

//! Creates the object with the given URL
/** @param $url The URL to use to connect to the remote server; if any protocol (URI scheme) is present, then it must be \c "ssh" or \c "ssh2"; with this variant the username and password can be set as well as the hostname and port

    @throw SFTPCLIENT-PARAMETER-ERROR unknown protocol passed in URL; no hostname in URL

    @par Example:
    @code my $sftpclient SFTPClient("ssh2://user:pass@host:port"); @endcode
 */
//# constructor(string $url) {}

//! Creates the object with the given hostname and port number
/** @param $host the remote host to connect to
    @param $port the port number on the remote host to connect to

    @throw SFTPCLIENT-PARAMETER-ERROR empty hostname passed

    @par Example:
    @code my $sftpclient SFTPClient("host", 4022); @endcode
 */
//# constructor(string $host, softint $port) {}
void SFTPC_constructor(QoreObject *self, const QoreListNode *params, ExceptionSink *xsink) {
   QORE_TRACE("SFTPC_constructor");

   const QoreStringNode *p0 = HARD_QORE_STRING(params, 0);

   QoreURL url(p0);

   if (!url.getHost()) {
      xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "no hostname found in URL '%s'", p0->getBuffer());
      return;
   }

   if (url.getProtocol() && strcasecmp("sftp", url.getProtocol()->getBuffer())) {
      xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "URL given in the first argument to SFTPClient::constructor() specifies invalid protocol '%s' (expecting 'sftp')", url.getProtocol()->getBuffer());
      return;
   }

   // create private data object
   SSH2Client *mySFTPClient = new SFTPClient(url, get_int_param(params, 1));
   self->setPrivate(CID_SFTP_CLIENT, mySFTPClient);
}

//! Throws an exception; currently SFTPClient objects cannot be copied
/** @throw SFTPCLIENT-COPY-ERROR copying SFTPClient objects is not currently implemented
 */
//# SSH2Client copy() {}
void SFTPC_copy(QoreObject *self, QoreObject *old, SFTPClient *myself, ExceptionSink *xsink) {
   xsink->raiseException("SFTPCLIENT-COPY-ERROR", "copying sftp connection objects is not allowed");
}

//! Returns a hash with information about the current connection status
/** this method is safe to call when not connected

    @return a hash with the following keys:
    - \c ssh2host: (string) the host name of the remote server
    - \c ssh2port: (int) the port number of the remote server
    - \c ssh2user: (string) the user name used for the connection
    - \c keyfile_priv: (string) the filename of the local private key file used
    - \c keyfile_pub: (string) the filename of the local public key file used
    - \c fingerprint: (*string) The fingerprint of the public host key of the remote server as a string of hex digit pairs separated by colons (:), ex: \c "AC:AA:DF:3F:49:82:5A:1A:DE:C9:ED:14:00:7D:65:9E" or \c NOTHING if not connected
    - \c authenticated: (*string) a string giving the authentication mechanism used: \c "publickey", \c "password", \c "keyboard-interactive" or \c NOTHING if not connected
    - \c connected: (bool) tells if the connection is currently active or not
    - \c methods: (hash) a hash of strings giving the crytographic methods used for the connection
    - \c path: (*string) a string giving the path name set in the object or \c NOTHING if no path is set

    @par Example:
    @code my hash $h = $sftpclient.info(); @endcode
*/
//# hash info() {}
static AbstractQoreNode *SFTPC_info(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   return myself->sftp_info();
}

//! Returns the current path as a string or \c NOTHING if no path is set
/** @return the current path as a string or \c NOTHING if no path is set

    @par Example:
    @code my *string $path = $sftpclient.path(); @endcode
*/
//# *string path() {}
static AbstractQoreNode *SFTPC_path(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   return myself->sftp_path();
}

//! Returns a hash of directory information; throws an exception if any errors occur
/** @param $path The pathname of the directory to list

    @return a hash with the following keys containing  and sorted lists of directory, file, or symbolic link names, respectively: 
    - \c path: the path used
    - \c directories: sorted list of subdirectory names in the directory
    - \c files: sorted list of file names in the directory
    - \c links: sorted list of symbolic links in the directory

    @throw SFTPCLIENT-NOT-CONNECTED client is not connected
    @throw SFTPCLIENT-LIST-ERROR failed to list directory

    @par Example:
    @code my hash $h = $sftpclient.list($path); @endcode
*/
//# hash list(string $path) {}
static AbstractQoreNode *SFTPC_list_str(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   return myself->sftp_list(HARD_QORE_STRING(params, 0)->getBuffer(), xsink);
}

//! Returns a hash of directory information; throws an exception if any errors occur
/** @return a hash with the following keys containing  and sorted lists of directory, file, or symbolic link names, respectively: 
    - \c path: the path used
    - \c directories: sorted list of subdirectory names in the directory
    - \c files: sorted list of file names in the directory
    - \c links: sorted list of symbolic links in the directory

    @throw SFTPCLIENT-NOT-CONNECTED client is not connected
    @throw SFTPCLIENT-LIST-ERROR failed to list directory

    @par Example:
    @code my hash $h = $sftpclient.list(); @endcode
*/
//# hash list() {}
static AbstractQoreNode *SFTPC_list(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   return myself->sftp_list(0, xsink);
}

static QoreHashNode *attr2hash(const LIBSSH2_SFTP_ATTRIBUTES &attr) {
   QoreHashNode *ret = new QoreHashNode;

   if (attr.flags & LIBSSH2_SFTP_ATTR_SIZE)
      ret->setKeyValue("size", new QoreBigIntNode(attr.filesize), 0);
   if (attr.flags & LIBSSH2_SFTP_ATTR_ACMODTIME) {
      ret->setKeyValue("atime", DateTimeNode::makeAbsolute(currentTZ(), (int64)attr.atime), 0);
      ret->setKeyValue("mtime", DateTimeNode::makeAbsolute(currentTZ(), (int64)attr.mtime), 0);
   }
   if (attr.flags & LIBSSH2_SFTP_ATTR_UIDGID) {
      ret->setKeyValue("uid", new QoreBigIntNode(attr.uid), 0);
      ret->setKeyValue("gid", new QoreBigIntNode(attr.gid), 0);
   }
   if (attr.flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) {
      ret->setKeyValue("mode", new QoreBigIntNode(attr.permissions), 0);
      ret->setKeyValue("permissions", new QoreStringNode(mode2str(attr.permissions)), 0);
   }
  
   return ret;
}

//! Returns a hash of information about a file or \c NOTHING if the file cannot be found
/** @param $path the pathname of the file to stat

    @return \c NOTHING if the path was not found or a hash with the following keys (note that some hash keys may not be present if the data was not returned from the remote server):
    - \c size: (int) the size of the file in bytes
    - \c atime: (date) the date/time the file was last accessed
    - \c mtime: (date) the date/time the file was last modified
    - \c uid: (int) the userid of the file's owner
    - \c gid: (int) the groupid of the file
    - \c mode: (int) the mode of the file as an integer
    - \c permissions: (string) a string giving the symbolic mode of the file

    @throw SFTPCLIENT-NOT-CONNECTED no connection has been established
    @throw SSH2-ERROR socket error sending data; timeout on socket; invalid SFTP protocol response; server returned an error message    

    @par Example:
    @code my *hash $h = $sftpclient.stat($path); @endcode
*/
//# *hash stat(string $path) {}
static AbstractQoreNode *SFTPC_stat(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0 = HARD_QORE_STRING(params, 0);

   LIBSSH2_SFTP_ATTRIBUTES attr;
   int rc = myself->sftp_getAttributes(p0->getBuffer(), &attr, xsink);

   return rc < 0 ? 0 : attr2hash(attr);
}

//! Deletes a file on the server side; throws an exception if any errors occur
/** @param $path the pathname of the file to delete

    @throw SFTPCLIENT-NOT-CONNECTED no connection has been established
    @throw SSH2-ERROR socket error sending data; timeout on socket; invalid SFTP protocol response; server returned an error message    

    @par Example:
    @code $sftpclient.removeFile($path); @endcode
*/
//# nothing removeFile(string $path) {}
static AbstractQoreNode *SFTPC_removeFile(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0 = HARD_QORE_STRING(params, 0);

   myself->sftp_unlink(p0->getBuffer(), xsink);
   return 0;
}

//! Renames or moves a remote file; throws an exception if any errors occur
/** Note that this command is executed with the \c LIBSSH2_SFTP_RENAME_OVERWRITE option set to \c True, but that this option is commonly ignored by sshd servers, in which case i the target file already exists, an \c SSH2-ERROR exception will be raised

    @param $old the old pathname of the file
    @param $new the new pathname of the file

    @throw SFTPCLIENT-NOT-CONNECTED no connection has been established
    @throw SSH2-ERROR socket error sending data; timeout on socket; invalid SFTP protocol response; server returned an error message; file exists and server does not allow overwriting

    @par Example:
    @code $sftpclient.name("file.txt", "file.txt.orig"); @endcode
*/
//# nothing rename(string $old, string $new) {}
static AbstractQoreNode *SFTPC_rename(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0 = HARD_QORE_STRING(params, 0);
   const QoreStringNode *p1 = HARD_QORE_STRING(params, 1);

   myself->sftp_rename(p0->getBuffer(), p1->getBuffer(), xsink);
   return 0;
}

//! Changes the mode of a remote file or directory; sticky bits may not be set; throws an exception if any errors occur
/** @param $path the pathname of the file or directory to update
    @param $mode the new mode to set

    @throw SFTPCLIENT-PARAMETER-ERROR mode setting is only possible for user, group and other (no sticky bits)
    @throw SFTPCLIENT-NOT-CONNECTED no connection has been established
    @throw SSH2-ERROR socket error sending data; timeout on socket; invalid SFTP protocol response; server returned an error message    

    @par Example:
    @code $sftpclient.chmod("file.txt", 0600); @endcode
*/
//# nothing chmod(string $path, int $mode) {}
static AbstractQoreNode *SFTPC_chmod(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0 = HARD_QORE_STRING(params, 0);
   unsigned int mode = HARD_QORE_INT(params, 1);

   // check if mode is in range
   if (mode != (mode & SFTP_UGOMASK)) {
      xsink->raiseException("SFTPCLIENT-PARAMETER-ERROR", "mode setting is only possible for user, group and other (no sticky bits)");
      return 0;
   }

   myself->sftp_chmod(p0->getBuffer(), mode, xsink);
   return 0;
}

//! Retrieves a remote file and returns it as a binary object; throws an exception if any errors occur
/** @param $path the pathname of the file to retrieve

    @throw SFTPCLIENT-NOT-CONNECTED no connection has been established
    @throw SSH2-ERROR socket error sending data; timeout on socket; invalid SFTP protocol response; server returned an error message    

    @par Example:
    @code my binary $b = $sftpclient.getFile("file.bin"); @endcode
*/
//# binary getFile(string $path) {}
static AbstractQoreNode *SFTPC_getFile(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0 = HARD_QORE_STRING(params, 0);
   return myself->sftp_getFile(p0->getBuffer(), xsink);
}

//! Retrieves a remote file and returns it as a string; throws an exception if any errors occur
/** @param $path the pathname of the file to retrieve

    @throw SFTPCLIENT-NOT-CONNECTED no connection has been established
    @throw SSH2-ERROR socket error sending data; timeout on socket; invalid SFTP protocol response; server returned an error message    

    @par Example:
    @code my string $str = $sftpclient.getTextFile("file.txt"); @endcode
*/
//# string getTextFile(string $path) {}
static AbstractQoreNode *SFTPC_getTextFile(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0 = HARD_QORE_STRING(params, 0);
   return myself->sftp_getTextFile(p0->getBuffer(), xsink);
}

//! Saves a file on the remote server from a binary argument and returns the number of bytes sent; throws an exception if any errors occur
/** @param $bin the file data as a binary object
    @param $path the remote path name on the server
    @param $mode the mode of the file on the server

    @return the number of bytes actually sent

    @throw SFTPCLIENT-NOT-CONNECTED no connection has been established
    @throw SSH2-ERROR socket error sending data; timeout on socket; invalid SFTP protocol response; server returned an error message

    @par Example:
    @code my int $size = $sftpclient.putFile($bin, "file.bin", 0600); @endcode
*/
//# int putFile(binary $bin, string $path, int $mode = 0644) {}
static AbstractQoreNode *SFTPC_putFile_bin(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const BinaryNode *bn = HARD_QORE_BINARY(params, 0);
   const QoreStringNode *p1 = HARD_QORE_STRING(params, 1);
   int mode = HARD_QORE_INT(params, 2);

   // transfer the file
   int rc = myself->sftp_putFile((const char *)bn->getPtr(), bn->size(), p1->getBuffer(), mode, xsink);

   return *xsink ? 0 : new QoreBigIntNode(rc);
}

//! Saves a file on the remote server from a string argument and returns the number of bytes sent; throws an exception if any errors occur
/** @param $data the file data as a string
    @param $path the remote path name on the server
    @param $mode the mode of the file on the server

    @return the number of bytes actually sent

    @throw SFTPCLIENT-NOT-CONNECTED no connection has been established
    @throw SSH2-ERROR socket error sending data; timeout on socket; invalid SFTP protocol response; server returned an error message

    @par Example:
    @code my int $size = $sftpclient.putFile($str, "file.bin", 0600); @endcode
*/
//# int putFile(string $data, string $path, int $mode = 0644) {}
static AbstractQoreNode *SFTPC_putFile_str(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0 = HARD_QORE_STRING(params, 0);
   const QoreStringNode *p1 = HARD_QORE_STRING(params, 1);
   int mode = HARD_QORE_INT(params, 2);

   // transfer the file
   int rc = myself->sftp_putFile(p0->getBuffer(), p0->strlen(), p1->getBuffer(), mode, xsink);

   return *xsink ? 0 : new QoreBigIntNode(rc);
}

//! Makes a directory on the remote server; throws an exception if any errors occur
/** @param $path The pathname of the new directory
    @param $mode the mode of the new directory

    @throw SFTPCLIENT-MKDIR-ERROR directory name is an empty string
    @throw SFTPCLIENT-NOT-CONNECTED no connection has been established
    @throw SSH2-ERROR socket error sending data; timeout on socket; invalid SFTP protocol response; server returned an error message

    @par Example:
    @code $sftpclient.mkdir($path, 0700); @endcode
*/
//# nothing mkdir(string $path, int $mode = 0755) {}
static AbstractQoreNode *SFTPC_mkdir(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0 = HARD_QORE_STRING(params, 0);
   int mode = HARD_QORE_INT(params, 1);

   myself->sftp_mkdir(p0->getBuffer(), mode, xsink);

   return 0;
}

//! Removes a directory on the remote server; throws an exception if any errors occur
/** @param $path The pathname of the directory to remove

    @throw SFTPCLIENT-RMDIR-ERROR directory name is an empty string
    @throw SFTPCLIENT-NOT-CONNECTED no connection has been established
    @throw SSH2-ERROR socket error sending data; timeout on socket; invalid SFTP protocol response; server returned an error message

    @par Example:
    @code $sftpclient.rmdir($path); @endcode
*/
//# nothing rmdir(string $path) {}
static AbstractQoreNode *SFTPC_rmdir(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0 = HARD_QORE_STRING(params, 0);

   myself->sftp_rmdir(p0->getBuffer(), xsink);

   return 0;
}

//! Changes the directory on the remote server and returns the new directory; throws an exception if any errors occur
/** @param $path The pathname of the directory to change to

    @throw SFTPCLIENT-NOT-CONNECTED no connection has been established
    @throw SSH2-ERROR socket error sending data; timeout on socket; invalid SFTP protocol response; server returned an error message

    @par Example:
    @code $sftpclient.chdir($path); @endcode
*/
//# string chdir(string $path) {}
static AbstractQoreNode *SFTPC_chdir(QoreObject *self, SFTPClient *myself, const QoreListNode *params, ExceptionSink *xsink) {
   const QoreStringNode *p0 = HARD_QORE_STRING(params, 0);

   return myself->sftp_chdir(p0? p0->getBuffer(): 0, xsink);
}

/**# };
};
*/

/**
 * class init
 */
QoreClass *initSFTPClientClass(QoreClass *ssh2base) {
   QORE_TRACE("initSFTPClient()");

   QoreClass *QC_SFTP_CLIENT=new QoreClass("SFTPClient", QDOM_NETWORK);

   QC_SFTP_CLIENT->addBuiltinVirtualBaseClass(ssh2base);

   CID_SFTP_CLIENT=QC_SFTP_CLIENT->getID();

   // SFTPClient::constructor(string $url)
   // SFTPClient::constructor(string $host, softint $port)
   QC_SFTP_CLIENT->setConstructorExtended(SFTPC_constructor, false, QC_NO_FLAGS, QDOM_DEFAULT, 1, stringTypeInfo, QORE_PARAM_NO_ARG);
   QC_SFTP_CLIENT->setConstructorExtended(SFTPC_constructor, false, QC_NO_FLAGS, QDOM_DEFAULT, 2, stringTypeInfo, QORE_PARAM_NO_ARG, softBigIntTypeInfo, QORE_PARAM_NO_ARG);

   QC_SFTP_CLIENT->setCopy((q_copy_t)SFTPC_copy);

   // SFTPClient::info() returns hash
   QC_SFTP_CLIENT->addMethodExtended("info",       (q_method_t)SFTPC_info, false, QC_RET_VALUE_ONLY, QDOM_DEFAULT, hashTypeInfo);

   // SFTPClient::path() returns *string
   QC_SFTP_CLIENT->addMethodExtended("path",       (q_method_t)SFTPC_path, false, QC_RET_VALUE_ONLY, QDOM_DEFAULT, stringOrNothingTypeInfo);

   // SFTPClient::list(string $path) returns hash
   QC_SFTP_CLIENT->addMethodExtended("list",       (q_method_t)SFTPC_list_str, false, QC_NO_FLAGS, QDOM_DEFAULT, hashTypeInfo, 1, stringTypeInfo, QORE_PARAM_NO_ARG);
   // SFTPClient::list() returns hash
   QC_SFTP_CLIENT->addMethodExtended("list",       (q_method_t)SFTPC_list, false, QC_NO_FLAGS, QDOM_DEFAULT, hashTypeInfo);

   // SFTPClient::stat(string $filename) returns *hash
   QC_SFTP_CLIENT->addMethodExtended("stat",       (q_method_t)SFTPC_stat, false, QC_NO_FLAGS, QDOM_DEFAULT, hashOrNothingTypeInfo, 1, stringTypeInfo, QORE_PARAM_NO_ARG);

   // SFTPClient::removeFile(string $filename) returns nothing
   QC_SFTP_CLIENT->addMethodExtended("removeFile", (q_method_t)SFTPC_removeFile, false, QC_NO_FLAGS, QDOM_DEFAULT, nothingTypeInfo, 1, stringTypeInfo, QORE_PARAM_NO_ARG);

   // SFTPClient::rename(string $old, string $new) returns nothing
   QC_SFTP_CLIENT->addMethodExtended("rename",     (q_method_t)SFTPC_rename, false, QC_NO_FLAGS, QDOM_DEFAULT, nothingTypeInfo, 2, stringTypeInfo, QORE_PARAM_NO_ARG, stringTypeInfo, QORE_PARAM_NO_ARG);

   // SFTPClient::chmod(string $path, int $mode) returns nothing
   QC_SFTP_CLIENT->addMethodExtended("chmod",      (q_method_t)SFTPC_chmod, false, QC_NO_FLAGS, QDOM_DEFAULT, nothingTypeInfo, 2, stringTypeInfo, QORE_PARAM_NO_ARG, bigIntTypeInfo, QORE_PARAM_NO_ARG);

   // SFTPClient::putFile(binary $data, string $path, int $mode = 0644) returns int
   QC_SFTP_CLIENT->addMethodExtended("putFile",    (q_method_t)SFTPC_putFile_bin, false, QC_NO_FLAGS, QDOM_DEFAULT, bigIntTypeInfo, 3, binaryTypeInfo, QORE_PARAM_NO_ARG, stringTypeInfo, QORE_PARAM_NO_ARG, bigIntTypeInfo, new QoreBigIntNode(0644));
   // SFTPClient::putFile(string $data, string $path, int $mode = 0644) returns int
   QC_SFTP_CLIENT->addMethodExtended("putFile",    (q_method_t)SFTPC_putFile_str, false, QC_NO_FLAGS, QDOM_DEFAULT, bigIntTypeInfo, 3, stringTypeInfo, QORE_PARAM_NO_ARG, stringTypeInfo, QORE_PARAM_NO_ARG, bigIntTypeInfo, new QoreBigIntNode(0644));

   // SFTPClient::getFile(string $path) returns binary
   QC_SFTP_CLIENT->addMethodExtended("getFile",    (q_method_t)SFTPC_getFile, false, QC_NO_FLAGS, QDOM_DEFAULT, binaryTypeInfo, 1, stringTypeInfo, QORE_PARAM_NO_ARG);

   // SFTPClient::getTextFile(string $path) returns string
   QC_SFTP_CLIENT->addMethodExtended("getTextFile", (q_method_t)SFTPC_getTextFile, false, QC_NO_FLAGS, QDOM_DEFAULT, stringTypeInfo, 1, stringTypeInfo, QORE_PARAM_NO_ARG);

   // SFTPClient::mkdir(string $path, int $mode = 0755) returns nothing
   QC_SFTP_CLIENT->addMethodExtended("mkdir",       (q_method_t)SFTPC_mkdir, false, QC_NO_FLAGS, QDOM_DEFAULT, bigIntTypeInfo, 2, stringTypeInfo, QORE_PARAM_NO_ARG, bigIntTypeInfo, new QoreBigIntNode(0755));

   // SFTPClient::rmdir(string $path) returns nothing
   QC_SFTP_CLIENT->addMethodExtended("rmdir",       (q_method_t)SFTPC_rmdir, false, QC_NO_FLAGS, QDOM_DEFAULT, nothingTypeInfo, 1, stringTypeInfo, QORE_PARAM_NO_ARG);

   // SFTPClient::chdir(string $path) returns string
   QC_SFTP_CLIENT->addMethodExtended("chdir",       (q_method_t)SFTPC_chdir, false, QC_NO_FLAGS, QDOM_DEFAULT, nothingTypeInfo, 1, stringTypeInfo, QORE_PARAM_NO_ARG);

   return QC_SFTP_CLIENT;
}
