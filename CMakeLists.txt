# TODO: Add defines for solaris and hp-ux.
# TODO: Maybe not depend on cmake 3 but the project command is nice in cmake 3.

cmake_minimum_required(VERSION 3.0.0)

project(qore-ssh2-module VERSION 1.1.0)

include(CheckCXXCompilerFlag)
include(CheckCXXSymbolExists)
include(CheckIncludeFileCXX)

find_package(Qore 0.8.6 REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSSH2 REQUIRED libssh2>=1.1)

set(CMAKE_THREAD_PREFER_PTHREAD ON)
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
if(CMAKE_USE_PTHREADS_INIT)
message(STATUS "Found POSIX Threads: TRUE")
else(CMAKE_USE_PTHREADS_INIT)
message(STATUS "Found POSIX Threads: FALSE")
message(FATAL_ERROR "POSIX threads do not seem to be supported on this platform, aborting")
endif()

include_directories(${LIBSSH2_INCLUDE_DIRS})
include_directories(${CMAKE_SOURCE_DIR}/src)

check_include_file_cxx(arpa/inet.h HAVE_ARPA_INET_H)
check_include_file_cxx(pwd.h HAVE_PWD_H)
check_include_file_cxx(stdint.h HAVE_STDINT_H)
check_include_file_cxx(sys/socket.h HAVE_SYS_SOCKET_H)
check_include_file_cxx(sys/time.h HAVE_SYS_TIME_H)
check_include_file_cxx(unistd.h HAVE_UNISTD_H)

# Check for C++11.
include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++11" COMPILER_SUPPORTS_CXX11)
if(COMPILER_SUPPORTS_CXX11)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
else()
    message(FATAL_ERROR "The compiler ${CMAKE_CXX_COMPILER} has no C++11 support. Please use a different C++ compiler.")
endif()

set(CMAKE_REQUIRED_INCLUDES ${LIBSSH2_INCLUDE_DIRS})
set(CMAKE_REQUIRED_LIBRARIES ${LIBSSH2_LDFLAGS})
check_cxx_symbol_exists(libssh2_session_handshake libssh2.h HAVE_LIBSSH2_SESSION_HANDSHAKE)
check_cxx_symbol_exists(libssh2_keepalive_config libssh2.h HAVE_LIBSSH2_KEEPALIVE_CONFIG)
unset(CMAKE_REQUIRED_INCLUDES)
unset(CMAKE_REQUIRED_LIBRARIES)

check_cxx_compiler_flag(-fvisibility=hidden HAVE_GCC_VISIBILITY)

if(${CMAKE_SYSTEM_NAME} EQUAL "Linux")
add_definitions(-D_GNU_SOURCE)
endif()

configure_file(${CMAKE_SOURCE_DIR}/cmake/config.h.cmake
               ${CMAKE_BINARY_DIR}/config.h)

set(QPP_SRC
    src/QC_SFTPClient.qpp
    src/QC_SSH2Base.qpp
    src/QC_SSH2Channel.qpp
    src/QC_SSH2Client.qpp
)

set(CPP_SRC
    src/SFTPClient.cpp
    src/SSH2Channel.cpp
    src/SSH2Client.cpp
    src/ssh2-module.cpp
)

set(QMOD
    qlib/SftpPoller.qm
    qlib/Ssh2Connections.qm
)

qore_wrap_qpp_value(QPP_SOURCES ${QPP_SRC})

set(module_name "ssh2")

add_library(${module_name} SHARED ${CPP_SRC} ${QPP_SOURCES})

qore_binary_module(${module_name} ${PROJECT_VERSION} ${LIBSSH2_LDFLAGS} Threads::Threads)
qore_user_modules(${QMOD})

qore_dist(${PROJECT_VERSION})

qore_config_info()
