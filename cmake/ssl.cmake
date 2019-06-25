# Copyright (c) 2009, 2019, Oracle and/or its affiliates. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA 

# We support different versions of SSL:
# - "system"  (typically) uses headers/libraries in /usr/lib and /usr/lib64
# - a custom installation of openssl can be used like this
#     - cmake -DCMAKE_PREFIX_PATH=</path/to/custom/openssl> -DWITH_SSL="system"
#   or
#     - cmake -DWITH_SSL=</path/to/custom/openssl>
#
# The default value for WITH_SSL is "system"
# set in cmake/build_configurations/feature_set.cmake
#
# WITH_SSL="system" means: use the SSL library that comes with the operating
# system. This typically means you have to do 'yum install openssl-devel'
# or something similar.
#
# For Windows or macOS, WITH_SSL="system" is handled a bit differently:
# We assume you have installed
#     https://slproweb.com/products/Win32OpenSSL.html
#     We look for "C:/OpenSSL-Win64/"
#     The .dll files must be in your PATH.
# or
#     http://brewformulas.org/Openssl
#     We look for "/usr/local/opt/openssl"
#     We look for the static libraries, rather than the .dylib ones.
# When the package has been located, we treat it as if cmake had been
# invoked with  -DWITH_SSL=</path/to/custom/openssl>


SET(WITH_SSL_DOC "\nsystem (use the OS openssl library)")
SET(WITH_SSL_DOC
  "${WITH_SSL_DOC}, \nyes (synonym for system)")
SET(WITH_SSL_DOC
  "${WITH_SSL_DOC}, \n</path/to/custom/openssl/installation>")

STRING(REPLACE "\n" "| " WITH_SSL_DOC_STRING "${WITH_SSL_DOC}")
MACRO (CHANGE_SSL_SETTINGS string)
  SET(WITH_SSL ${string} CACHE STRING ${WITH_SSL_DOC_STRING} FORCE)
ENDMACRO()

MACRO(FATAL_SSL_NOT_FOUND_ERROR string)
  MESSAGE(STATUS "\n${string}"
    "\nMake sure you have specified a supported SSL version. "
    "\nValid options are : ${WITH_SSL_DOC}\n"
    )
  IF(UNIX)
    MESSAGE(FATAL_ERROR
      "Please install the appropriate openssl developer package.\n")
  ENDIF()
  IF(WIN32)
    MESSAGE(FATAL_ERROR
      "Please see https://wiki.openssl.org/index.php/Binaries\n")
  ENDIF()
  IF(APPLE)
    MESSAGE(FATAL_ERROR
      "Please see http://brewformulas.org/Openssl\n")
  ENDIF()
ENDMACRO()

MACRO(RESET_SSL_VARIABLES)
  UNSET(WITH_SSL_PATH)
  UNSET(WITH_SSL_PATH CACHE)
  UNSET(OPENSSL_ROOT_DIR)
  UNSET(OPENSSL_ROOT_DIR CACHE)
  UNSET(OPENSSL_INCLUDE_DIR)
  UNSET(OPENSSL_INCLUDE_DIR CACHE)
  UNSET(OPENSSL_APPLINK_C)
  UNSET(OPENSSL_APPLINK_C CACHE)
  UNSET(OPENSSL_LIBRARY)
  UNSET(OPENSSL_LIBRARY CACHE)
  UNSET(CRYPTO_LIBRARY)
  UNSET(CRYPTO_LIBRARY CACHE)
  UNSET(HAVE_SHA512_DIGEST_LENGTH)
  UNSET(HAVE_SHA512_DIGEST_LENGTH CACHE)
ENDMACRO()

# MYSQL_CHECK_SSL
#
# Provides the following configure options:
# WITH_SSL=[yes|system|<path/to/custom/installation>]
MACRO (MYSQL_CHECK_SSL)
  IF(NOT WITH_SSL)
    CHANGE_SSL_SETTINGS("system")
  ENDIF()

  # See if WITH_SSL is of the form </path/to/custom/installation>
  FILE(GLOB WITH_SSL_HEADER ${WITH_SSL}/include/openssl/ssl.h)
  IF (WITH_SSL_HEADER)
    FILE(TO_CMAKE_PATH "${WITH_SSL}" WITH_SSL)
    SET(WITH_SSL_PATH ${WITH_SSL} CACHE PATH "path to custom SSL installation")
    SET(WITH_SSL_PATH ${WITH_SSL})
  ENDIF()

  IF(WITH_SSL STREQUAL "system" OR
      WITH_SSL STREQUAL "yes" OR
      WITH_SSL_PATH
      )
    # Treat "system" the same way as -DWITH_SSL=</path/to/custom/openssl>
    # Note: we cannot use FIND_PACKAGE(OpenSSL), as older cmake versions
    # have buggy implementations.
    IF((APPLE OR WIN32) AND NOT WITH_SSL_PATH AND WITH_SSL STREQUAL "system")
      IF(APPLE)
        SET(WITH_SSL_PATH "/usr/local/opt/openssl")
      ELSE()
        SET(WITH_SSL_PATH "C:/OpenSSL-Win64/")
        # OpenSSL-1.1 requires backport of the patch for
        # Bug #28179051: ADD SUPPORT FOR OPENSSL 1.1 ON WINDOWS
        # SET(WITH_SSL_PATH "C:/OpenSSL-1.1-Win64/")
      ENDIF()
    ENDIF()

    # First search in WITH_SSL_PATH.
    FIND_PATH(OPENSSL_ROOT_DIR
      NAMES include/openssl/ssl.h
      NO_CMAKE_PATH
      NO_CMAKE_ENVIRONMENT_PATH
      HINTS ${WITH_SSL_PATH}
    )
    # Then search in standard places (if not found above).
    FIND_PATH(OPENSSL_ROOT_DIR
      NAMES include/openssl/ssl.h
    )

    FIND_PATH(OPENSSL_INCLUDE_DIR
      NAMES openssl/ssl.h
      HINTS ${OPENSSL_ROOT_DIR}/include
    )

    IF (WIN32)
      FIND_FILE(OPENSSL_APPLINK_C
        NAMES openssl/applink.c
        HINTS ${OPENSSL_ROOT_DIR}/include
      )
      MESSAGE(STATUS "OPENSSL_APPLINK_C ${OPENSSL_APPLINK_C}")
    ENDIF()

    # On mac this list is <.dylib;.so;.a>
    # We prefer static libraries, so we revert it here.
    IF (WITH_SSL_PATH)
      LIST(REVERSE CMAKE_FIND_LIBRARY_SUFFIXES)
      MESSAGE(STATUS "suffixes <${CMAKE_FIND_LIBRARY_SUFFIXES}>")
    ENDIF()

    FIND_LIBRARY(OPENSSL_LIBRARY
                 NAMES ssl libssl ssleay32 ssleay32MD
                 HINTS ${OPENSSL_ROOT_DIR}/lib)
    FIND_LIBRARY(CRYPTO_LIBRARY
                 NAMES crypto libcrypto libeay32
                 HINTS ${OPENSSL_ROOT_DIR}/lib)
    IF (WITH_SSL_PATH)
      LIST(REVERSE CMAKE_FIND_LIBRARY_SUFFIXES)
    ENDIF()

    IF(OPENSSL_INCLUDE_DIR)
      # Verify version number. Version information looks like:
      #   #define OPENSSL_VERSION_NUMBER 0x1000103fL
      # Encoded as MNNFFPPS: major minor fix patch status
      FILE(STRINGS "${OPENSSL_INCLUDE_DIR}/openssl/opensslv.h"
        OPENSSL_VERSION_NUMBER
        REGEX "^#[ ]*define[\t ]+OPENSSL_VERSION_NUMBER[\t ]+0x[0-9].*"
        )
      STRING(REGEX REPLACE
        "^.*OPENSSL_VERSION_NUMBER[\t ]+0x([0-9]).*$" "\\1"
        OPENSSL_MAJOR_VERSION "${OPENSSL_VERSION_NUMBER}"
        )
      STRING(REGEX REPLACE
        "^.*OPENSSL_VERSION_NUMBER[\t ]+0x[0-9]([0-9][0-9]).*$" "\\1"
        OPENSSL_MINOR_VERSION "${OPENSSL_VERSION_NUMBER}"
        )
      STRING(REGEX REPLACE
        "^.*OPENSSL_VERSION_NUMBER[\t ]+0x[0-9][0-9][0-9]([0-9][0-9]).*$" "\\1"
        OPENSSL_FIX_VERSION "${OPENSSL_VERSION_NUMBER}"
        )
    ENDIF()
    IF("${OPENSSL_MAJOR_VERSION}.${OPENSSL_MINOR_VERSION}.${OPENSSL_FIX_VERSION}" VERSION_GREATER "1.1.0")
       ADD_DEFINITIONS(-DHAVE_TLSv13)
    ENDIF()
    IF(OPENSSL_INCLUDE_DIR AND
       OPENSSL_LIBRARY   AND
       CRYPTO_LIBRARY      AND
       OPENSSL_MAJOR_VERSION STREQUAL "1"
      )
      SET(OPENSSL_FOUND TRUE)
    ELSE()
      SET(OPENSSL_FOUND FALSE)
    ENDIF()

    # If we are invoked with -DWITH_SSL=/path/to/custom/openssl
    # and we have found static libraries, then link them statically
    # into our executables and libraries.
    # Adding IMPORTED_LOCATION allows MERGE_STATIC_LIBS
    # to get LOCATION and do correct dependency analysis.
    SET(MY_CRYPTO_LIBRARY "${CRYPTO_LIBRARY}")
    SET(MY_OPENSSL_LIBRARY "${OPENSSL_LIBRARY}")
    IF (WITH_SSL_PATH)
      GET_FILENAME_COMPONENT(CRYPTO_EXT "${CRYPTO_LIBRARY}" EXT)
      GET_FILENAME_COMPONENT(OPENSSL_EXT "${OPENSSL_LIBRARY}" EXT)
      IF (CRYPTO_EXT STREQUAL ".a" OR CRYPTO_EXT STREQUAL ".lib")
        SET(MY_CRYPTO_LIBRARY imported_crypto)
        ADD_LIBRARY(imported_crypto STATIC IMPORTED)
        SET_TARGET_PROPERTIES(imported_crypto
          PROPERTIES IMPORTED_LOCATION "${CRYPTO_LIBRARY}")
      ENDIF()
      IF (OPENSSL_EXT STREQUAL ".a" OR OPENSSL_EXT STREQUAL ".lib")
        SET(MY_OPENSSL_LIBRARY imported_openssl)
        ADD_LIBRARY(imported_openssl STATIC IMPORTED)
        SET_TARGET_PROPERTIES(imported_openssl
          PROPERTIES IMPORTED_LOCATION "${OPENSSL_LIBRARY}")
      ENDIF()
    ENDIF()

    MESSAGE(STATUS "OPENSSL_INCLUDE_DIR = ${OPENSSL_INCLUDE_DIR}")
    MESSAGE(STATUS "OPENSSL_LIBRARY = ${OPENSSL_LIBRARY}")
    MESSAGE(STATUS "CRYPTO_LIBRARY = ${CRYPTO_LIBRARY}")
    MESSAGE(STATUS "OPENSSL_MAJOR_VERSION = ${OPENSSL_MAJOR_VERSION}")
    MESSAGE(STATUS "OPENSSL_MINOR_VERSION = ${OPENSSL_MINOR_VERSION}")
    MESSAGE(STATUS "OPENSSL_FIX_VERSION = ${OPENSSL_FIX_VERSION}")

    INCLUDE(CheckSymbolExists)
    SET(CMAKE_REQUIRED_INCLUDES ${OPENSSL_INCLUDE_DIR})
    CHECK_SYMBOL_EXISTS(SHA512_DIGEST_LENGTH "openssl/sha.h"
                        HAVE_SHA512_DIGEST_LENGTH)
    IF(OPENSSL_FOUND AND HAVE_SHA512_DIGEST_LENGTH)
      SET(SSL_SOURCES "")
      SET(SSL_LIBRARIES ${MY_OPENSSL_LIBRARY} ${MY_CRYPTO_LIBRARY})
      IF(CMAKE_SYSTEM_NAME MATCHES "SunOS")
        SET(SSL_LIBRARIES ${SSL_LIBRARIES} ${LIBSOCKET})
      ENDIF()
      IF(CMAKE_SYSTEM_NAME MATCHES "Linux")
        SET(SSL_LIBRARIES ${SSL_LIBRARIES} ${LIBDL})
      ENDIF()
      MESSAGE(STATUS "SSL_LIBRARIES = ${SSL_LIBRARIES}")
      IF(WIN32 AND WITH_SSL STREQUAL "system")
        MESSAGE(STATUS "Please do\nPATH=${WITH_SSL_PATH}:$PATH")
      ENDIF()
      SET(SSL_INCLUDE_DIRS ${OPENSSL_INCLUDE_DIR})
      SET(SSL_INTERNAL_INCLUDE_DIRS "")
      SET(SSL_DEFINES "-DHAVE_OPENSSL")
    ELSE()
      RESET_SSL_VARIABLES()
      FATAL_SSL_NOT_FOUND_ERROR(
        "Cannot find appropriate system libraries for WITH_SSL=${WITH_SSL}.")
    ENDIF()
  ELSE()
    RESET_SSL_VARIABLES()
    FATAL_SSL_NOT_FOUND_ERROR(
      "Wrong option or path for WITH_SSL=${WITH_SSL}.")
  ENDIF()
ENDMACRO()
