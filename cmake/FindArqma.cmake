#------------------------------------------------------------------------------
# CMake helper for the majority of the cpp-ethereum modules.
#
# This module defines
#     ARQMA_XXX_LIBRARIES, the libraries needed to use ethereum.
#     ARQMA_FOUND, If false, do not try to use ethereum.
#
# File addetped from cpp-ethereum
#
# The documentation for cpp-ethereum is hosted at http://cpp-ethereum.org
#
# ------------------------------------------------------------------------------
# This file is part of cpp-ethereum.
#
# cpp-ethereum is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# cpp-ethereum is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with cpp-ethereum.  If not, see <http://www.gnu.org/licenses/>
#
# (c) 2014-2016 cpp-ethereum contributors.
#------------------------------------------------------------------------------

set(LIBS common;blocks;cryptonote_basic;cryptonote_core;multisig;net;
         cryptonote_protocol;daemonizer;mnemonics;epee;lmdb;device;
         blockchain_db;ringct;wallet;cncrypto;easylogging;version;checkpoints)

set(Arqma_INCLUDE_DIRS "${CPP_ARQMA_DIR}")

# if the project is a subset of main cpp-ethereum project
# use same pattern for variables as Boost uses

foreach (l ${LIBS})

	string(TOUPPER ${l} L)

	find_library(Arqma_${L}_LIBRARY
		NAMES ${l}
		PATHS ${CMAKE_LIBRARY_PATH}
		PATH_SUFFIXES "/src/${l}" "/src/" "/external/db_drivers/lib${l}" "/lib" "/src/crypto" "/contrib/epee/src" "/external/easylogging++/" "/external/${l}"
		NO_DEFAULT_PATH
	)

	set(Arqma_${L}_LIBRARIES ${Arqma_${L}_LIBRARY})

	message(STATUS FindArqma " Arqma_${L}_LIBRARIES ${Arqma_${L}_LIBRARY}")

	add_library(${l} STATIC IMPORTED)
	set_property(TARGET ${l} PROPERTY IMPORTED_LOCATION ${Arqma_${L}_LIBRARIES})

endforeach()

if (EXISTS ${ARQMA_BUILD_DIR}/src/ringct/libringct_basic.a)
	message(STATUS FindArqma " found libringct_basic.a")
	add_library(ringct_basic STATIC IMPORTED)
	set_property(TARGET ringct_basic
			PROPERTY IMPORTED_LOCATION ${ARQMA_BUILD_DIR}/src/ringct/libringct_basic.a)
endif()

if(EXISTS ${ARQMA_BUILD_DIR}/external/randomarq/librandomx.a)
  message(STATUS FindArqma " found librandomx.a")
  add_library(randomx STATIC IMPORTED)
  set_property(TARGET randomx PROPERTY IMPORTED_LOCATION ${ARQMA_BUILD_DIR}/external/randomarq/librandomx.a)
endif()

message(STATUS ${ARQMA_SOURCE_DIR}/build)

# include arqma headers
include_directories(
    ${ARQMA_SOURCE_DIR}/src
    ${ARQMA_SOURCE_DIR}/src/crypto
    ${ARQMA_SOURCE_DIR}/external
    ${ARQMA_SOURCE_DIR}/external/randomarq/src
    ${ARQMA_SOURCE_DIR}/build/Linux/release-v0.6.0/release
    ${ARQMA_SOURCE_DIR}/external/easylogging++
    ${ARQMA_SOURCE_DIR}/contrib/epee/include
    ${ARQMA_SOURCE_DIR}/external/db_drivers/liblmdb)
