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

#include <string.h>

// thread-local storage for password for faked keyboard-interactive authentication
TLKeyboardPassword keyboardPassword;

// maybe needed for the hidden classes...

static class QoreNamespace *ssh2ns; // namespace

#ifndef QORE_MONOLITHIC
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
  ssh2ns=new QoreNamespace("SSH2");

  // all classes belonging to here
  //  amqns->addSystemClass(initActiveMQSessionClass());
  ssh2ns->addSystemClass(initSSH2ClientClass());
  ssh2ns->addSystemClass(initSFTPClientClass());

  /*
  // delivery modes
  amqns->addConstant("AMQ_DEL_PERSISTENT", new QoreBigIntNode(AMQ_DEL_PERSISTENT));
  amqns->addConstant("AMQ_DEL_NONPERSISTENT", new QoreBigIntNode(AMQ_DEL_NONPERSISTENT));

  // session constants
  amqns->addConstant("AMQ_ACK_AUTO", new QoreBigIntNode(AMQ_ACK_AUTO));
  amqns->addConstant("AMQ_ACK_DUPOK", new QoreBigIntNode(AMQ_ACK_DUPOK));
  amqns->addConstant("AMQ_ACK_CLIENT", new QoreBigIntNode(AMQ_ACK_CLIENT));
  amqns->addConstant("AMQ_ACK_SESSION", new QoreBigIntNode(AMQ_ACK_SESSION));

  // destination type constants
  amqns->addConstant("AMQ_QUEUE", new QoreBigIntNode(AMQ_QUEUE));
  amqns->addConstant("AMQ_TOPIC", new QoreBigIntNode(AMQ_TOPIC));
  */
}

class QoreStringNode *ssh2_module_init() {
   setup_namespace();

   // add builtin functions
   //builtinFunctions.add("tibae_type", f_tibae_type);
   return NULL;
}

void ssh2_module_ns_init(class QoreNamespace *rns, class QoreNamespace *qns) {
   QORE_TRACE("ssh2_module_ns_init()");

   qns->addInitialNamespace(ssh2ns->copy());
}

void ssh2_module_delete() {
   QORE_TRACE("ssh2_module_delete()");
   delete ssh2ns;
}

