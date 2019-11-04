#!/bin/bash

set -e
set -x

ENV_FILE=/tmp/env.sh

. ${ENV_FILE}

# setup MODULE_SRC_DIR env var
cwd=`pwd`
if [ "${MODULE_SRC_DIR}" = "" ]; then
    if [ -e "$cwd/src/ssh2-module.cpp" ]; then
        MODULE_SRC_DIR=$cwd
    else
        MODULE_SRC_DIR=$WORKDIR/module-ssh2
    fi
fi
echo "export MODULE_SRC_DIR=${MODULE_SRC_DIR}" >> ${ENV_FILE}

echo "export QORE_UID=999" >> ${ENV_FILE}
echo "export QORE_GID=999" >> ${ENV_FILE}

. ${ENV_FILE}

export MAKE_JOBS=4
export QORE_HOME=/home/qore

# build module and install
echo && echo "-- building module --"
cd ${MODULE_SRC_DIR}
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=debug -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX}
make -j${MAKE_JOBS}
make install

# add Qore user and group
groupadd -o -g ${QORE_GID} qore
useradd -o -m -d ${QORE_HOME} -u ${QORE_UID} -g ${QORE_GID} qore

# generate SSH keys
gosu qore:qore ssh-keygen -q -f ${QORE_HOME}/.ssh/id_rsa -N ""
gosu qore:qore cp ${QORE_HOME}/.ssh/id_rsa.pub ${QORE_HOME}/.ssh/authorized_keys
gosu qore:qore echo "localhost `cat /etc/ssh/ssh_host_rsa_key.pub`" > ${QORE_HOME}/.ssh/known_hosts
gosu qore:qore echo "localhost `cat /etc/ssh/ssh_host_ecdsa_key.pub`" > ${QORE_HOME}/.ssh/known_hosts
chmod 600 ${QORE_HOME}/.ssh/authorized_keys

# own everything by the qore user
chown -R qore:qore ${MODULE_SRC_DIR} ${QORE_HOME}

# run SSH server
mkdir -p /var/run/sshd
/usr/sbin/sshd

# run the tests
export QORE_MODULE_DIR=${MODULE_SRC_DIR}/qlib:${QORE_MODULE_DIR}
cd ${MODULE_SRC_DIR}
for test in test/*.qtest; do
    gosu qore:qore qore $test -vv
done