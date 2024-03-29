cmake_minimum_required(VERSION 3.0.0)

project(qore-ssh2-module VERSION 1.4.2)

include(CheckCXXCompilerFlag)
include(CheckCXXSymbolExists)
include(CheckIncludeFileCXX)

find_package(Qore 1.0 REQUIRED)
find_package(OpenSSL REQUIRED)

if(WIN32 OR MSYS OR MINGW)
    set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
    if (DEFINED ENV{LIBSSH2_LIBRARY})
        set(LIBSSH2_LIBRARY $ENV{LIBSSH2_LIBRARY})
    endif()
    find_package(LibSSH2 REQUIRED)
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBSSH2 REQUIRED libssh2>=1.1)
endif()

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
include_directories(${OPENSSL_INCLUDE_DIR})
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

qore_wrap_qpp_value(QPP_SOURCES DOXLIST _dox_src ${QPP_SRC})

set(module_name "ssh2")

set(QORE_DOX_TMPL_SRC
  docs/mainpage.doxygen.tmpl
)

if (DEFINED ENV{DOXYGEN_EXECUTABLE})
    set(DOXYGEN_EXECUTABLE $ENV{DOXYGEN_EXECUTABLE})
endif()

add_library(${module_name} MODULE ${CPP_SRC} ${QPP_SOURCES})
set(MODULE_DOX_INPUT ${CMAKE_BINARY_DIR}/mainpage.dox ${_dox_src})
qore_external_binary_module(${module_name} ${PROJECT_VERSION} ${LIBSSH2_LDFLAGS})

qore_external_user_module("qlib/SftpPollerUtil.qm" "")
qore_external_user_module("qlib/SftpPoller.qm" "SftpPollerUtil")
qore_external_user_module("qlib/Ssh2Connections.qm" "")

qore_dist(${PROJECT_VERSION})

qore_config_info()

if (DOXYGEN_FOUND)
    qore_wrap_dox(QORE_DOX_SRC ${QORE_DOX_TMPL_SRC})
    add_custom_target(QORE_MOD_DOX_FILES DEPENDS ${QORE_DOX_SRC})
    add_dependencies(docs-module QORE_MOD_DOX_FILES)
endif()
