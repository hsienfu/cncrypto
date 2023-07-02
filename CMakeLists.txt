set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

list(INSERT CMAKE_MODULE_PATH 0
     "${CMAKE_CURRENT_SOURCE_DIR}/cmake"
     )
include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)
include(CheckLinkerFlag)
include(CheckLibraryExists)
include(CheckFunctionExists)
include(FindPythonInterp)

if (NOT DEFINED ENV{DEVELOPER_LOCAL_TOOLS})
  message(STATUS "Could not find DEVELOPER_LOCAL_TOOLS in env (not required)")
  set(BOOST_IGNORE_SYSTEM_PATHS_DEFAULT OFF)
elseif ("$ENV{DEVELOPER_LOCAL_TOOLS}" EQUAL 1)
  message(STATUS "Found: env DEVELOPER_LOCAL_TOOLS = 1")
  set(BOOST_IGNORE_SYSTEM_PATHS_DEFAULT ON)
else()
  message(STATUS "Found: env DEVELOPER_LOCAL_TOOLS = 0")
  set(BOOST_IGNORE_SYSTEM_PATHS_DEFAULT OFF)
endif()

message(STATUS "BOOST_IGNORE_SYSTEM_PATHS defaults to ${BOOST_IGNORE_SYSTEM_PATHS_DEFAULT}")
option(BOOST_IGNORE_SYSTEM_PATHS "Ignore boost system paths for local boost installation" ${BOOST_IGNORE_SYSTEM_PATHS_DEFAULT})

cmake_minimum_required(VERSION 3.5)
message(STATUS "CMake version ${CMAKE_VERSION}")

project(bccrypto)
enable_language(C ASM)

# Require C11/C++11 and disable extensions for all targets
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(COVERAGE "Enable profiling for test coverage report" OFF)
if(COVERAGE)
    message(STATUS "Building with profiling for test coverage report")
endif()
macro (monero_enable_coverage)
  if(COVERAGE)
    foreach(COV_FLAG -fprofile-arcs -ftest-coverage --coverage)
      set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   ${COV_FLAG}")
      set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${COV_FLAG}")
    endforeach()
  endif()
endmacro()

# Finds all headers in a directory and its subdirs, to be able to search for them and autosave in IDEs.
#
# Parameters:
# - headers_found:    Output variable, which will hold the found headers
# - module_root_dir:  The search path for the headers. Typically it will be the module's root dir, so "${CMAKE_CURRENT_SOURCE_DIR}" or a derivative of it.
macro (monero_find_all_headers headers_found module_root_dir)
  file(GLOB ${headers_found}
           "${module_root_dir}/*.h*"    # h* will include hpps as well.
           "${module_root_dir}/**/*.h*" # Any number of subdirs will be included.
           "${module_root_dir}/*.inl"   # .inl is typically template code and is being treated as headers (it's being included).
           "${module_root_dir}/**/*.inl"
)
endmacro()

option(RELINK_TARGETS "Relink targets, when just a dependant .so changed, but not its header?" OFF)
function (monero_set_target_no_relink target)
  if (RELINK_TARGETS MATCHES OFF)
    # Will not relink the target, when just its dependant .so has changed, but not it's interface
    set_target_properties("${target}" PROPERTIES LINK_DEPENDS_NO_SHARED true)
  endif()
endfunction()

option(STRIP_TARGETS "Strip symbols from targets?" OFF)
function (monero_set_target_strip target)
  if (STRIP_TARGETS)
    set_target_properties("${target}" PROPERTIES LINK_FLAGS_RELEASE -s)
    set_target_properties("${target}" PROPERTIES LINK_FLAGS_DEBUG -s)
    # Stripping from Debug might make sense if you're low on disk space, but want to test if debug version builds properly.
  endif()
endfunction()

function (monero_add_minimal_executable name)
  source_group("${name}"
    FILES
      ${ARGN})

  add_executable("${name}"
    ${ARGN})
    monero_set_target_no_relink("${name}")
    monero_set_target_strip    ("${name}")
endfunction()

function (monero_add_library name)
    monero_add_library_with_deps(NAME "${name}" SOURCES ${ARGN})
endfunction()

function (monero_add_library_with_deps)
  cmake_parse_arguments(MONERO_ADD_LIBRARY "" "NAME" "DEPENDS;SOURCES" ${ARGN})
  source_group("${MONERO_ADD_LIBRARY_NAME}" FILES ${MONERO_ADD_LIBRARY_SOURCES})

  # Define a ("virtual") object library and an actual library that links those
  # objects together. The virtual libraries can be arbitrarily combined to link
  # any subset of objects into one library archive. This is used for releasing
  # libwallet, which combines multiple components.
  set(objlib obj_${MONERO_ADD_LIBRARY_NAME})
  add_library(${objlib} OBJECT ${MONERO_ADD_LIBRARY_SOURCES})
  add_library("${MONERO_ADD_LIBRARY_NAME}" $<TARGET_OBJECTS:${objlib}>)
  monero_set_target_no_relink("${MONERO_ADD_LIBRARY_NAME}")
  monero_set_target_strip    ("${MONERO_ADD_LIBRARY_NAME}")
  if (MONERO_ADD_LIBRARY_DEPENDS)
    add_dependencies(${objlib} ${MONERO_ADD_LIBRARY_DEPENDS})
  endif()
  set_property(TARGET "${MONERO_ADD_LIBRARY_NAME}" PROPERTY FOLDER "libs")
  target_compile_definitions(${objlib}
    PRIVATE $<TARGET_PROPERTY:${MONERO_ADD_LIBRARY_NAME},INTERFACE_COMPILE_DEFINITIONS>)
endfunction ()

option(STATIC "Link libraries statically" OFF)

# This is a CMake built-in switch that concerns internal libraries
set(BUILD_SHARED_LIBS_DEFAULT OFF)
if (NOT STATIC AND CMAKE_BUILD_TYPE_LOWER STREQUAL "debug")
	set(BUILD_SHARED_LIBS_DEFAULT ON)
endif()
option(BUILD_SHARED_LIBS "Build internal libraries as shared" ${BUILD_SHARED_LIBS_DEFAULT})

if (BUILD_SHARED_LIBS)
  message(STATUS "Building internal libraries with position independent code")
  add_definitions("-DBUILD_SHARED_LIBS")
else()
  message(STATUS "Building internal libraries as static")
endif()
set(PIC_FLAG "-fPIC")

if(STATIC)
  set(CMAKE_FIND_LIBRARY_SUFFIXES .a ${CMAKE_FIND_LIBRARY_SUFFIXES})
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DZMQ_STATIC")
endif()

if (${BOOST_IGNORE_SYSTEM_PATHS} STREQUAL "ON")
  set(Boost_NO_SYSTEM_PATHS TRUE)
endif()

set(OLD_LIB_SUFFIXES ${CMAKE_FIND_LIBRARY_SUFFIXES})
set(Boost_NO_BOOST_CMAKE ON)
if(STATIC)
  set(Boost_USE_STATIC_LIBS ON)
  set(Boost_USE_STATIC_RUNTIME ON)
endif()
find_package(Boost 1.58 QUIET REQUIRED COMPONENTS system filesystem thread date_time chrono regex serialization program_options locale)
add_definitions(-DBOOST_ASIO_ENABLE_SEQUENTIAL_STRAND_ALLOCATION)

set(CMAKE_FIND_LIBRARY_SUFFIXES ${OLD_LIB_SUFFIXES})
if(NOT Boost_FOUND)
  die("Could not find Boost libraries, please make sure you have installed Boost or libboost-all-dev (>=1.58) or the equivalent")
elseif(Boost_FOUND)
  message(STATUS "Found Boost Version: ${Boost_VERSION}")
  if (Boost_VERSION VERSION_LESS 10 AND Boost_VERSION VERSION_LESS 1.62.0 AND NOT (OPENSSL_VERSION VERSION_LESS 1.1))
    set(BOOST_BEFORE_1_62 true)
  endif()
  if (NOT Boost_VERSION VERSION_LESS 10 AND Boost_VERSION VERSION_LESS 106200 AND NOT (OPENSSL_VERSION VERSION_LESS 1.1))
    set(BOOST_BEFORE_1_62 true)
  endif()
  if (BOOST_BEFORE_1_62)
      message(FATAL_ERROR "Boost ${Boost_VERSION} (older than 1.62) is too old to link with OpenSSL ${OPENSSL_VERSION} (1.1 or newer) found at ${OPENSSL_INCLUDE_DIR} and ${OPENSSL_LIBRARIES}. "
                          "Update Boost or install OpenSSL 1.0 and set path to it when running cmake: "
                          "cmake -DOPENSSL_ROOT_DIR='/usr/include/openssl-1.0'")
  endif()
endif()

include_directories(SYSTEM ${Boost_INCLUDE_DIRS})
include_directories(easylogging++ epee/include)

add_subdirectory(easylogging++)
add_subdirectory(epee)


