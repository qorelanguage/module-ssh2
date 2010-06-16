/*
  modules/ssh2/ssh2-module.cc

  SSH2/SFTP integration to QORE

  Qore Programming Language

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

#include "ssh2-module.h"
#include "QC_SSH2Base.h"
#include "SSH2Client.h"
#include "SFTPClient.h"
#include "SSH2Channel.h"

#include <string.h>

// thread-local storage for password for faked keyboard-interactive authentication
TLKeyboardPassword keyboardPassword;

// maybe needed for the hidden classes...

static QoreNamespace ssh2ns("SSH2"); // namespace

// for verifying the minimum required version of the library
static const char *qore_libssh2_version = 0;

#ifndef QORE_MONOLITHIC
static QoreStringNode *ssh2_module_init();
static void ssh2_module_ns_init(QoreNamespace *rns, QoreNamespace *qns);
static void ssh2_module_delete();

DLLEXPORT char qore_module_name[] = "ssh2";
DLLEXPORT char qore_module_version[] = "1.0.2";
DLLEXPORT char qore_module_description[] = "SSH2/SFTP client module";
DLLEXPORT char qore_module_author[] = "Wolfgang Ritzinger";
DLLEXPORT char qore_module_url[] = "http://qore.sourceforge.net";
DLLEXPORT int qore_module_api_major = QORE_MODULE_API_MAJOR;
DLLEXPORT int qore_module_api_minor = QORE_MODULE_API_MINOR;
DLLEXPORT qore_module_init_t qore_module_init = ssh2_module_init;
DLLEXPORT qore_module_ns_init_t qore_module_ns_init = ssh2_module_ns_init;
DLLEXPORT qore_module_delete_t qore_module_delete = ssh2_module_delete;
DLLEXPORT qore_license_t qore_module_license = QL_LGPL;
#endif

static void setup_namespace() {
   // setup static "master" namespace

   QoreClass *SSH2Base, *SSH2Channel;

  // all classes belonging to here
   ssh2ns.addSystemClass((SSH2Base = initSSH2BaseClass()));
   ssh2ns.addSystemClass((SSH2Channel = initSSH2ChannelClass()));
   ssh2ns.addSystemClass(initSSH2ClientClass(SSH2Base, SSH2Channel));
   ssh2ns.addSystemClass(initSFTPClientClass(SSH2Base));

   // constants
   ssh2ns.addConstant("Version", new QoreStringNode(qore_libssh2_version));
}

static QoreStringNode *ssh2_module_init() {
   qore_libssh2_version = libssh2_version(LIBSSH2_VERSION_NUM);
   if (!qore_libssh2_version) {
      QoreStringNode *err = new QoreStringNode("the runtime version of the library is too old; got '%s', expecting minimum version '");
      err->concat(LIBSSH2_VERSION);
      err->concat('\'');
      return err;
   }

   setup_namespace();

   // add builtin functions
   //builtinFunctions.add("tibae_type", f_tibae_type);
   return NULL;
}

static void ssh2_module_ns_init(QoreNamespace *rns, QoreNamespace *qns) {
   QORE_TRACE("ssh2_module_ns_init()");

   qns->addInitialNamespace(ssh2ns.copy());
}

static void ssh2_module_delete() {
   QORE_TRACE("ssh2_module_delete()");
}
