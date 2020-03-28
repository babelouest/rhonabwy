#
# Rhonabwy library
#
# CMake file used to build all programs
#
# Copyright 2018 Silvio Clecio <silvioprog@gmail.com>
# Copyright 2020 Nicolas Mora <mail@babelouest.org>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the MIT License
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#

cmake_minimum_required(VERSION 3.5)

project(rhonabwy C)

set(CMAKE_C_STANDARD 99)
if (NOT MSVC)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror")
endif()

# library info

set(PROJECT_DESCRIPTION "Create, modify, parse or export Json Web Keys as defined in the RFC 7517")
set(PROJECT_HOMEPAGE_URL "https://github.com/babelouest/rhonabwy/")
set(PROJECT_BUGREPORT_PATH "https://github.com/babelouest/rhonabwy/issues")
set(LIBRARY_VERSION_MAJOR "0")
set(LIBRARY_VERSION_MINOR "9")
set(LIBRARY_VERSION_PATCH "7")
set(ORCANIA_VERSION_REQUIRED "2.1.0")
set(YDER_VERSION_REQUIRED "1.4.10")
set(ULFIUS_VERSION_REQUIRED "2.6.5")

set(PROJECT_VERSION "${LIBRARY_VERSION_MAJOR}.${LIBRARY_VERSION_MINOR}.${LIBRARY_VERSION_PATCH}")
set(PROJECT_VERSION_MAJOR ${LIBRARY_VERSION_MAJOR})
set(PROJECT_VERSION_MINOR ${LIBRARY_VERSION_MINOR})
set(PROJECT_VERSION_PATCH ${LIBRARY_VERSION_PATCH})

if (${LIBRARY_VERSION_MAJOR} VERSION_LESS 10)
    set (LIBRARY_VERSION_MAJOR_PAD "0${LIBRARY_VERSION_MAJOR}")
else ()
    set (LIBRARY_VERSION_MAJOR_PAD "${LIBRARY_VERSION_MAJOR}")
endif ()
if (${LIBRARY_VERSION_MINOR} VERSION_LESS 10)
    set (LIBRARY_VERSION_MINOR_PAD "0${LIBRARY_VERSION_MINOR}")
else ()
    set (LIBRARY_VERSION_MINOR_PAD "${LIBRARY_VERSION_MINOR}")
endif ()
if (${LIBRARY_VERSION_PATCH} VERSION_LESS 10)
    set (LIBRARY_VERSION_PATCH_PAD "0${LIBRARY_VERSION_PATCH}")
else ()
    set (LIBRARY_VERSION_PATCH_PAD "${LIBRARY_VERSION_PATCH}")
endif ()
set(PROJECT_VERSION_NUMBER "${LIBRARY_VERSION_MAJOR_PAD}${LIBRARY_VERSION_MINOR_PAD}${LIBRARY_VERSION_PATCH_PAD}")

set(LIBRARY_VERSION "${LIBRARY_VERSION_MAJOR}.${LIBRARY_VERSION_MINOR}.${LIBRARY_VERSION_PATCH}")
set(LIBRARY_SOVERSION "${LIBRARY_VERSION_MAJOR}.${LIBRARY_VERSION_MINOR}")

# cmake modules

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake-modules)

include(GNUInstallDirs)
include(CheckSymbolExists)

# check if _GNU_SOURCE is available

if (NOT _GNU_SOURCE)
    check_symbol_exists(__GNU_LIBRARY__ "features.h" _GNU_SOURCE)

    if (NOT _GNU_SOURCE)
        unset(_GNU_SOURCE CACHE)
        check_symbol_exists(_GNU_SOURCE "features.h" _GNU_SOURCE)
    endif ()
endif ()

if (_GNU_SOURCE)
    add_definitions(-D_GNU_SOURCE)
endif ()

include(FindJansson)
set(JANSSON_MIN_VERSION 2.4)
find_package(Jansson ${JANSSON_MIN_VERSION} REQUIRED)
if (JANSSON_FOUND)
	set(LIBS ${LIBS} ${JANSSON_LIBRARIES})
	include_directories(${JANSSON_INCLUDE_DIRS})
endif ()

include(FindGnuTLS)
find_package(GnuTLS REQUIRED)
if (GNUTLS_FOUND)
	set(LIBS ${LIBS} ${GNUTLS_LIBRARIES})
	include_directories(${GNUTLS_INCLUDE_DIRS})
endif ()

# directories and source

set(INC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

include_directories(${INC_DIR})

set(LIB_SRC
        ${INC_DIR}/rhonabwy.h # allow many IDEs to find and edit it
        ${SRC_DIR}/jwk.c
        ${SRC_DIR}/jwks.c
	${SRC_DIR}/jws.c)

set(PKGCONF_REQ "")
set(PKGCONF_REQ_PRIVATE "")

# static library

option(BUILD_STATIC "Build static library." OFF)

if (BUILD_STATIC)
    add_library(rhonabwy_static STATIC ${LIB_SRC})
    target_compile_definitions(rhonabwy_static PUBLIC -DO_STATIC_LIBRARY)
    set_target_properties(rhonabwy_static PROPERTIES
            OUTPUT_NAME rhonabwy)
endif ()

# shared library

add_library(rhonabwy SHARED ${LIB_SRC})
set_target_properties(rhonabwy PROPERTIES
        COMPILE_OPTIONS -Wextra
        PUBLIC_HEADER "${INC_DIR}/rhonabwy.h;${PROJECT_BINARY_DIR}/rhonabwy-cfg.h"
        VERSION "${LIBRARY_VERSION}"
        SOVERSION "${LIBRARY_SOVERSION}")
target_link_libraries(rhonabwy ${LIBS})

set(SEARCH_ORCANIA OFF CACHE BOOL "Force to false") # Avoid to search and download orcania during yder search and download
set(SEARCH_ORCANIA_U OFF CACHE BOOL "Force to false") # Avoid to search and download orcania during ulfius search and download
set(SEARCH_YDER OFF CACHE BOOL "Force to false") # Avoid to search and download yder during ulfius and hoel search and download

option(DOWNLOAD_DEPENDENCIES "Download required dependencies" ON)

option(SEARCH_ORCANIA_R "Search for ORCANIA library" ON)
if (SEARCH_ORCANIA_R)
    set(Orcania_FIND_QUIETLY ON) # force to find Orcania quietly
    include(FindOrcania)
    find_package(Orcania ${ORCANIA_VERSION_REQUIRED} QUIET) # try to find orcania
    if (NOT ORCANIA_FOUND)
	if (DOWNLOAD_DEPENDENCIES)
	    include(DownloadProject)
	    message(STATUS "Download Orcania ${ORCANIA_VERSION_REQUIRED}")
	    download_project(PROJ orcania # ... otherwise, download archive
			    URL "https://github.com/babelouest/orcania/archive/v${ORCANIA_VERSION_REQUIRED}.tar.gz"
			    QUIET)
	    add_subdirectory(${orcania_SOURCE_DIR} ${orcania_BINARY_DIR})
	    include_directories(${orcania_SOURCE_DIR}/include)
	    add_dependencies(rhonabwy orcania)
	    set(ORCANIA_LIBRARIES orcania)
	    include_directories(${orcania_BINARY_DIR})
        else ()
            message( FATAL_ERROR "Orcania not found")
        endif ()
    endif ()
    target_link_libraries(rhonabwy ${LIBS} ${ORCANIA_LIBRARIES})
    set(LIBS ${LIBS} ${ORCANIA_LIBRARIES})
endif ()

option(SEARCH_YDER_R "Search for YDER library" ON)
if (SEARCH_YDER_R)
    set(Yder_FIND_QUIETLY ON) # force to find Yder quietly
    include(FindYder)
    find_package(Yder ${YDER_VERSION_REQUIRED} QUIET) # try to find Yder
    if (NOT YDER_FOUND)
	if (DOWNLOAD_DEPENDENCIES)
	    include(DownloadProject)
	    message(STATUS "Download Yder ${YDER_VERSION_REQUIRED}")
	    option(CHECK_ORCANIA "specific param" off)
	    download_project(PROJ yder # ... otherwise, download archive
			    URL "https://github.com/babelouest/yder/archive/v${YDER_VERSION_REQUIRED}.tar.gz"
			    QUIET)
	    add_subdirectory(${yder_SOURCE_DIR} ${yder_BINARY_DIR})
	    include_directories(${yder_SOURCE_DIR}/include)
	    include_directories(${orcania_SOURCE_DIR}/include)
	    add_dependencies(rhonabwy yder)
	    set(YDER_LIBRARIES yder)
	    include_directories(${yder_BINARY_DIR})
        else ()
            message( FATAL_ERROR "Yder not found")
        endif ()
    endif ()
    target_link_libraries(rhonabwy ${LIBS} ${YDER_LIBRARIES})
    set(LIBS ${LIBS} ${YDER_LIBRARIES})
endif ()

option(SEARCH_ULFIUS_R "Search for ULFIUS library" ON)
if (SEARCH_ULFIUS_R)
    set(Ulfius_FIND_QUIETLY ON)
    include(FindUlfius)
    find_package(Ulfius ${ULFIUS_VERSION_REQUIRED} QUIET)
    if (NOT ULFIUS_FOUND)
	if (DOWNLOAD_DEPENDENCIES)
	    include(DownloadProject)
	    option(CHECK_ORCANIA "specific param" off)
	    option(CHECK_YDER "specific param" off)
	    message(STATUS "Download Ulfius ${ULFIUS_VERSION_REQUIRED}")
	    download_project(PROJ ulfius
			    URL "https://github.com/babelouest/ulfius/archive/v${ULFIUS_VERSION_REQUIRED}.tar.gz"
			    QUIET)
	    add_subdirectory(${ulfius_SOURCE_DIR} ${ulfius_BINARY_DIR})
	    include_directories(${yder_SOURCE_DIR}/include)
	    include_directories(${orcania_SOURCE_DIR}/include)
	    include_directories(${ulfius_SOURCE_DIR}/include)
	    add_dependencies(rhonabwy ulfius)
	    set(ULFIUS_LIBRARIES ulfius)
	    include_directories(${ulfius_BINARY_DIR})
        else ()
            message( FATAL_ERROR "Ulfius not found")
        endif ()
    endif ()
    target_link_libraries(rhonabwy ${LIBS} ${ULFIUS_LIBRARIES})
    set(LIBS ${LIBS} ${ULFIUS_LIBRARIES})
endif ()

# documentation

option(BUILD_RHONABWY_DOCUMENTATION "Build the documentation." OFF)
if (BUILD_RHONABWY_DOCUMENTATION)
    find_package(Doxygen)
    if (DOXYGEN_FOUND)
        set(doxyfile_in ${CMAKE_CURRENT_SOURCE_DIR}/doc/doxygen.cfg)
        set(doxyfile ${CMAKE_CURRENT_BINARY_DIR}/doxyfile)
        
        configure_file(${doxyfile_in} ${doxyfile} @ONLY)
        
        add_custom_target(doc
                          COMMAND ${DOXYGEN_EXECUTABLE} ${doxyfile_in}
                          WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                          COMMENT "Generating documentation with Doxygen"
                          VERBATIM)

    else ()
        message(FATAL_ERROR "Doxygen is needed to build the documentation.")
    endif ()
endif ()

# build rhonabwy-cfg.h file
configure_file(${INC_DIR}/rhonabwy-cfg.h.in ${PROJECT_BINARY_DIR}/rhonabwy-cfg.h)
set (CMAKE_EXTRA_INCLUDE_FILES ${PROJECT_BINARY_DIR})
include_directories(${PROJECT_BINARY_DIR})

# tests

option(BUILD_RHONABWY_TESTING "Build the testing tree." OFF) # because we do not use include(CTest)

if (BUILD_RHONABWY_TESTING)
    include(FindCheck)
    find_package(Check REQUIRED)
    if (CHECK_FOUND)
		include(FindSubunit)
		find_package(Subunit REQUIRED)
        find_package(Threads REQUIRED)

        enable_testing()

        set(CMAKE_CTEST_COMMAND ctest -V)

        set(TST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/test)
        set(LIBS rhonabwy ${LIBS} ${CHECK_LIBRARIES} ${SUBUNIT_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} "-lm -lrt")

        set(TESTS
            jwk_core
            jwk_export
	    jwk_import
	    jwks_core
	    jws_core
	    jws_hmac
	    jws_ecdsa
	    jws_rsa
	    jws_rsapss
	    )

        configure_file(
                "${CMAKE_MODULE_PATH}/CTestCustom.cmake.in"
                "${CMAKE_CURRENT_BINARY_DIR}/CTestCustom.cmake"
                @ONLY)

        foreach (t ${TESTS})
            add_executable(${t} EXCLUDE_FROM_ALL ${TST_DIR}/${t}.c)
            target_include_directories(${t} PUBLIC ${TST_DIR})
            target_link_libraries(${t} PUBLIC ${LIBS})
            add_test(NAME ${t}
                    WORKING_DIRECTORY ${TST_DIR}
                    COMMAND ${t})
        endforeach ()
    endif ()
endif ()

# install target

option(INSTALL_HEADER "Install the header files" ON) # Install rhonabwy.h or not

configure_file(librhonabwy.pc.in librhonabwy.pc @ONLY)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/librhonabwy.pc
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

set(TARGETS rhonabwy)

if (INSTALL_HEADER)
    install(TARGETS ${TARGETS}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
            PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
else ()
    install(TARGETS ${TARGETS}
            RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
endif ()

# uninstall target

if (NOT TARGET uninstall)
    configure_file(
            "${CMAKE_MODULE_PATH}/CMakeUninstall.cmake.in"
            "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
            IMMEDIATE @ONLY)
    add_custom_target(uninstall
            COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif ()

# packaging

set(CPACK_PACKAGE_VERSION_MAJOR ${LIBRARY_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${LIBRARY_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${LIBRARY_VERSION_PATCH})

if (INSTALL_HEADER)
    set(PACKAGE_FILE_NAME
            "lib${CMAKE_PROJECT_NAME}-dev_${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")
else ()
    set(PACKAGE_FILE_NAME
            "lib${CMAKE_PROJECT_NAME}_${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH}")
endif ()
set(PACKAGE_IGNORED_FILES
        "${CMAKE_CURRENT_BINARY_DIR}/;/.git/;.gitignore;~$;${CPACK_SOURCE_IGNORE_FILES}")

set(CPACK_PACKAGE_NAME "librhonabwy")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Handle the flow of OAuth2 and OpenID Connect authentication process from the client side")
set(CPACK_GENERATOR "TGZ;DEB")
set(CPACK_PACKAGE_VERSION_MAJOR ${LIBRARY_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${LIBRARY_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${LIBRARY_VERSION_PATCH})

option(BUILD_RPM "Build a RPM for your system" OFF)
if (BUILD_RPM)
  set(CPACK_GENERATOR "TGZ;DEB;RPM")
  set(CPACK_RPM_PACKAGE_LICENSE "LGPL")
  set(CPACK_RPM_PACKAGE_URL "http://babelouest.github.io/rhonabwy/")
endif ()

set(CPACK_DEBIAN_PACKAGE_MAINTAINER "mail@babelouest.org")
set(CPACK_DEBIAN_PACKAGE_DESCRIPTION ${PROJECT_DESCRIPTION})
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://github.com/babelouest/rhonabwy")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.4), liborcania|liborcania-dev (>= ${ORCANIA_VERSION_REQUIRED}), libyder|libyder-dev (>= ${YDER_VERSION_REQUIRED})")
set(CPACK_PACKAGE_FILE_NAME ${PACKAGE_FILE_NAME})
set(CPACK_PACKAGE_FILE_NAME ${PACKAGE_FILE_NAME})

set(CPACK_SOURCE_GENERATOR "TGZ")
set(CPACK_SOURCE_PACKAGE_FILE_NAME ${PACKAGE_FILE_NAME})
set(CPACK_SOURCE_IGNORE_FILES ${PACKAGE_IGNORED_FILES})

include(CPack)

message(STATUS "Build testing tree:       ${BUILD_RHONABWY_TESTING}")
message(STATUS "Install the header files: ${INSTALL_HEADER}")
message(STATUS "Build Static library:     ${BUILD_STATIC}")
message(STATUS "Build RPM package:        ${BUILD_RPM}")
message(STATUS "Build documentation:      ${BUILD_RHONABWY_DOCUMENTATION}")
