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

function (add_c_flag_if_supported flag var)
  # Prepending the flag with -Werror will only add the flag,
  # if it doesn't result in generation of a warning of using a flag unknown to the compiler.
  set(TMP "-Werror ${flag}")
  string(REGEX REPLACE "[- ]" "_" supported ${TMP}_c)
  check_c_compiler_flag(${TMP} ${supported})
  if(${${supported}})
    set(${var} "${${var}} ${flag}" PARENT_SCOPE)
  endif()
endfunction()

function (add_cxx_flag_if_supported flag var)
  set(TMP "-Werror ${flag}")
  string(REGEX REPLACE "[- ]" "_" supported ${TMP}_cxx)
  check_cxx_compiler_flag(${TMP} ${supported})
  if(${${supported}})
    set(${var} "${${var}} ${flag}" PARENT_SCOPE)
  endif()
endfunction()

function (add_linker_flag_if_supported flag var)
  string(REPLACE "-" "_" supported ${flag}_ld)
  string(REPLACE "," "_" supported ${flag}_ld)
  check_linker_flag(${flag} ${supported})
  if(${${supported}})
    set(${var} "${${var}} ${flag}" PARENT_SCOPE)
  endif()
endfunction()

function (add_definition_if_function_found function var)
  string(REPLACE "-" "_" supported ${function}_function)
  check_function_exists(${function} ${supported})
  if(${${supported}})
    add_definitions("-D${var}")
  endif()
endfunction()

function (add_definition_if_library_exists library function header var)
  string(REPLACE "-" "_" supported ${function}_library)
  check_library_exists(${library} ${function} ${header} ${supported})
  if(${${supported}})
    add_definitions("-D${var}")
  endif()
endfunction()

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

add_definition_if_library_exists(c memset_s "string.h" HAVE_MEMSET_S)
add_definition_if_library_exists(c explicit_bzero "strings.h" HAVE_EXPLICIT_BZERO)
add_definition_if_function_found(strptime HAVE_STRPTIME)

add_definitions(-DAUTO_INITIALIZE_EASYLOGGINGPP)

set(MONERO_GENERATED_HEADERS_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated_include")
include_directories(${MONERO_GENERATED_HEADERS_DIR})

# As of OpenBSD 6.8, -march=<anything> breaks the build
function(set_default_arch)
  if (OPENBSD)
    set(ARCH default)
  else()
    set(ARCH native)
  endif()

  set(ARCH ${ARCH} CACHE STRING "CPU to build for: -march value or 'default' to not pass -march at all")
endfunction()

if (NOT (MSVC OR ARCH))
    set_default_arch()
endif()

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

function (monero_private_headers group)
  source_group("${group}\\Private"
    FILES
      ${ARGN})
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

include(TestCXXAcceptsFlag)
message(STATUS "Building on ${CMAKE_SYSTEM_PROCESSOR} for ${ARCH}")

set(ARCH_FLAG "-march=${ARCH}")
if(ARCH STREQUAL "native")
  check_c_compiler_flag(-march=native CC_SUPPORTS_MARCH_NATIVE)
  if (NOT CC_SUPPORTS_MARCH_NATIVE)
    check_c_compiler_flag(-mtune=native CC_SUPPORTS_MTUNE_NATIVE)
    if (CC_SUPPORTS_MTUNE_NATIVE)
      set(ARCH_FLAG "-mtune=${ARCH}")
    else()
      set(ARCH_FLAG "")
    endif()
  endif()
endif()

option(NO_AES "Explicitly disable AES support" ${NO_AES})

if(NO_AES)
  message(STATUS "AES support explicitly disabled")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNO_AES")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DNO_AES")
elseif(NOT ARM AND NOT PPC64LE AND NOT PPC64 AND NOT PPC AND NOT S390X AND NOT RISCV)
  message(STATUS "AES support enabled")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -maes")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -maes")
else()
  message(STATUS "AES support disabled")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${ARCH_FLAG}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${ARCH_FLAG}")

set(WARNINGS "-Wall -Wextra -Wpointer-arith -Wundef -Wvla -Wwrite-strings -Wno-error=extra -Wno-error=deprecated-declarations -Wno-unused-parameter -Wno-error=unused-variable -Wno-error=undef -Wno-error=uninitialized")
set(WARNINGS "${WARNINGS} -Wlogical-op -Wno-error=maybe-uninitialized -Wno-error=cpp")
set(C_WARNINGS "-Waggregate-return -Wnested-externs -Wold-style-definition -Wstrict-prototypes")
set(CXX_WARNINGS "-Wno-reorder -Wno-missing-field-initializers")
try_compile(STATIC_ASSERT_RES "${CMAKE_CURRENT_BINARY_DIR}/static-assert" "${CMAKE_CURRENT_SOURCE_DIR}/cmake/test-static-assert.c" CMAKE_FLAGS -DCMAKE_C_STANDARD=11)
if(STATIC_ASSERT_RES)
  set(STATIC_ASSERT_FLAG "")
else()
  set(STATIC_ASSERT_FLAG "-Dstatic_assert=_Static_assert")
endif()

try_compile(STATIC_ASSERT_CPP_RES "${CMAKE_CURRENT_BINARY_DIR}/static-assert" "${CMAKE_CURRENT_SOURCE_DIR}/cmake/test-static-assert.cpp" CMAKE_FLAGS -DCMAKE_CXX_STANDARD=11)
if(STATIC_ASSERT_CPP_RES)
  set(STATIC_ASSERT_CPP_FLAG "")
else()
  set(STATIC_ASSERT_CPP_FLAG "-Dstatic_assert=_Static_assert")
endif()

# With GCC 6.1.1 the compiled binary malfunctions due to aliasing. Until that
# is fixed in the code (Issue #847), force compiler to be conservative.
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-strict-aliasing")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-strict-aliasing")

# if those don't work for your compiler, single it out where appropriate
if(CMAKE_BUILD_TYPE STREQUAL "Release" AND NOT OPENBSD)
  set(C_SECURITY_FLAGS "${C_SECURITY_FLAGS} -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=1")
  set(CXX_SECURITY_FLAGS "${CXX_SECURITY_FLAGS} -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=1")
endif()

# warnings
add_c_flag_if_supported(-Wformat C_SECURITY_FLAGS)
add_cxx_flag_if_supported(-Wformat CXX_SECURITY_FLAGS)
add_c_flag_if_supported(-Wformat-security C_SECURITY_FLAGS)
add_cxx_flag_if_supported(-Wformat-security CXX_SECURITY_FLAGS)

# -fstack-protector
if (NOT OPENBSD AND NOT (WIN32 AND (CMAKE_C_COMPILER_ID STREQUAL "GNU" AND CMAKE_C_COMPILER_VERSION VERSION_LESS 9.1)))
  add_c_flag_if_supported(-fstack-protector C_SECURITY_FLAGS)
  add_cxx_flag_if_supported(-fstack-protector CXX_SECURITY_FLAGS)
  add_c_flag_if_supported(-fstack-protector-strong C_SECURITY_FLAGS)
  add_cxx_flag_if_supported(-fstack-protector-strong CXX_SECURITY_FLAGS)
endif()

# New in GCC 8.2
if (NOT OPENBSD AND NOT (WIN32 AND (CMAKE_C_COMPILER_ID STREQUAL "GNU" AND CMAKE_C_COMPILER_VERSION VERSION_LESS 9.1)))
  add_c_flag_if_supported(-fcf-protection=full C_SECURITY_FLAGS)
  add_cxx_flag_if_supported(-fcf-protection=full CXX_SECURITY_FLAGS)
endif()
if (NOT WIN32 AND NOT OPENBSD)
  add_c_flag_if_supported(-fstack-clash-protection C_SECURITY_FLAGS)
  add_cxx_flag_if_supported(-fstack-clash-protection CXX_SECURITY_FLAGS)
endif()

# Removed in GCC 9.1 (or before ?), but still accepted, so spams the output
if (NOT (CMAKE_C_COMPILER_ID STREQUAL "GNU" AND NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 9.1))
  add_c_flag_if_supported(-mmitigate-rop C_SECURITY_FLAGS)
  add_cxx_flag_if_supported(-mmitigate-rop CXX_SECURITY_FLAGS)
endif()

# linker
if (NOT SANITIZE AND NOT OSSFUZZ AND NOT (WIN32 AND (CMAKE_C_COMPILER_ID STREQUAL "GNU" AND (CMAKE_C_COMPILER_VERSION VERSION_LESS 9.1 OR NOT STATIC))))
  # PIE executables randomly crash at startup with ASAN
  # Windows binaries die on startup with PIE when compiled with GCC <9.x
  # Windows dynamically-linked binaries die on startup with PIE regardless of GCC version
  if ("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang")
    # Clang does not support -pie flag
    add_linker_flag_if_supported("-Wl,-pie" LD_SECURITY_FLAGS)
  else()
    add_linker_flag_if_supported("-pie" LD_SECURITY_FLAGS)
  endif()
endif()
add_linker_flag_if_supported(-Wl,-z,relro LD_SECURITY_FLAGS)
add_linker_flag_if_supported(-Wl,-z,now LD_SECURITY_FLAGS)
add_linker_flag_if_supported(-Wl,-z,noexecstack noexecstack_SUPPORTED)
if (noexecstack_SUPPORTED)
  set(LD_SECURITY_FLAGS "${LD_SECURITY_FLAGS} -Wl,-z,noexecstack")
endif()
add_linker_flag_if_supported(-Wl,-z,noexecheap noexecheap_SUPPORTED)
if (noexecheap_SUPPORTED)
  set(LD_SECURITY_FLAGS "${LD_SECURITY_FLAGS} -Wl,-z,noexecheap")
endif()

if(BACKCOMPAT)
    add_linker_flag_if_supported(-Wl,--wrap=__divmoddi4 LD_BACKCOMPAT_FLAGS)
    add_linker_flag_if_supported(-Wl,--wrap=glob LD_BACKCOMPAT_FLAGS)
    message(STATUS "Using Lib C back compat flags: ${LD_BACKCOMPAT_FLAGS}")
endif()

# Warnings, that when ignored are so severe, that they can segfault or even UB any application.
# Treat them as errors.
add_c_flag_if_supported(  -Werror=switch      C_SECURITY_FLAGS)
add_cxx_flag_if_supported(-Werror=switch      CXX_SECURITY_FLAGS)
add_c_flag_if_supported(  -Werror=return-type C_SECURITY_FLAGS)
add_cxx_flag_if_supported(-Werror=return-type CXX_SECURITY_FLAGS)

message(STATUS "Using C security hardening flags: ${C_SECURITY_FLAGS}")
message(STATUS "Using C++ security hardening flags: ${CXX_SECURITY_FLAGS}")
message(STATUS "Using linker security hardening flags: ${LD_SECURITY_FLAGS}")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_GNU_SOURCE ${MINGW_FLAG} ${STATIC_ASSERT_FLAG} ${WARNINGS} ${C_WARNINGS} ${PIC_FLAG} ${C_SECURITY_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_GNU_SOURCE ${MINGW_FLAG} ${STATIC_ASSERT_CPP_FLAG} ${WARNINGS} ${CXX_WARNINGS} ${PIC_FLAG} ${CXX_SECURITY_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${LD_SECURITY_FLAGS} ${LD_BACKCOMPAT_FLAGS}")

# With GCC 6.1.1 the compiled binary malfunctions due to aliasing. Until that
# is fixed in the code (Issue #847), force compiler to be conservative.
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-strict-aliasing")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-strict-aliasing")

# random crash on startup when asan is on if pie is enabled
if(NOT SANITIZE AND ANDROID AND NOT BUILD_GUI_DEPS STREQUAL "ON" OR IOS)
  #From Android 5: "only position independent executables (PIE) are supported" 
  message(STATUS "Enabling PIE executable")
  set(PIC_FLAG "")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIE")
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_CXX_FLAGS} -fPIE -pie")
endif()

set(DEBUG_FLAGS "-g3")

# At least some CLANGs default to not enough for monero
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -ftemplate-depth=900")

if(NOT DEFINED USE_LTO_DEFAULT)
  set(USE_LTO_DEFAULT false)
endif()
set(USE_LTO ${USE_LTO_DEFAULT} CACHE BOOL "Use Link-Time Optimization (Release mode only)")

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  # There is a clang bug that does not allow to compile code that uses AES-NI intrinsics if -flto is enabled, so explicitly disable
  set(USE_LTO false)
endif()


if(USE_LTO)
  set(RELEASE_FLAGS "${RELEASE_FLAGS} -flto")
  if(STATIC)
    set(RELEASE_FLAGS "${RELEASE_FLAGS} -ffat-lto-objects")
  endif()
  # Since gcc 4.9 the LTO format is non-standard (slim), so we need the gcc-specific ar and ranlib binaries
  if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND NOT (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 4.9.0) AND NOT OPENBSD AND NOT DRAGONFLY)
    # When invoking cmake on distributions on which gcc's binaries are prefixed
    # with an arch-specific triplet, the user must specify -DCHOST=<prefix>
    if (DEFINED CHOST)
      set(CMAKE_AR "${CHOST}-gcc-ar")
      set(CMAKE_RANLIB "${CHOST}-gcc-ranlib")
    else()
      set(CMAKE_AR "gcc-ar")
      set(CMAKE_RANLIB "gcc-ranlib")
    endif()
  endif()
endif()

set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} ${DEBUG_FLAGS}")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} ${DEBUG_FLAGS}")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} ${RELEASE_FLAGS}")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} ${RELEASE_FLAGS}")

if(STATIC)
  # STATIC already configures most deps to be linked in statically,
  # here we make more deps static if the platform permits it
  if (MINGW)
    # On Windows, this is as close to fully-static as we get:
    # this leaves only deps on /c/Windows/system32/*.dll
    set(STATIC_FLAGS "-static")
  elseif (NOT (APPLE OR FREEBSD OR OPENBSD OR DRAGONFLY))
    # On Linux, we don't support fully static build, but these can be static
    set(STATIC_FLAGS "-static-libgcc -static-libstdc++")
  endif()
  set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${STATIC_FLAGS} ")
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
include_directories(src external/easylogging++ external/epee/include)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)
enable_testing()

add_subdirectory(external)
add_subdirectory(src)
add_subdirectory(tests)

find_library(SODIUM_LIBRARY sodium)
find_library(RT rt)
find_library(Z z)
set(EXTRA_LIBRARIES ${RT} ${Z})
list(APPEND EXTRA_LIBRARIES ${CMAKE_DL_LIBS})
