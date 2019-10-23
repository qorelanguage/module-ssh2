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
useradd -o -m -d /home/qore -u ${QORE_UID} -g ${QORE_GID} qore

# generate SSH keys
gosu qore:qore ssh-keygen -q -f /home/qore/.ssh/id_rsa -N ""
gosu qore:qore cp /home/qore/.ssh/id_rsa.pub /home/qore/.ssh/authorized_keys
chmod 600 /home/qore/.ssh/authorized_keys

# own everything by the qore user
chown -R qore:qore ${MODULE_SRC_DIR} /home/qore

# run SSH server
mkdir -p /var/run/sshd
/usr/sbin/sshd

echo "/usr/share/qore-modules:"
ls -R /usr/share/qore-modules
echo
echo "/usr/lib/x86_64-linux-gnu/qore-modules:"
ls -R /usr/lib/x86_64-linux-gnu/qore-modules

# run the tests
export QORE_MODULE_DIR=${MODULE_SRC_DIR}/qlib:${QORE_MODULE_DIR}
cd ${MODULE_SRC_DIR}
for test in test/*.qtest; do
    gosu qore:qore qore $test -vv
done