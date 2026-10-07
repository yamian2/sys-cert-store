include(ExternalProject)
include("${CMAKE_CURRENT_LIST_DIR}/patched-dependency.cmake")
find_package(Perl REQUIRED)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
find_program(SCS_MAKE NAMES gmake make REQUIRED)
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_CROSSCOMPILING)
    message(FATAL_ERROR "Bundled crypto currently supports native Linux builds only.")
endif()

set(openssl_source "${PROJECT_SOURCE_DIR}/third_party/openssl")
foreach(required "${openssl_source}/Configure"
        "${PROJECT_SOURCE_DIR}/third_party/scossl/SymCryptProvider/src/p_scossl_base.c"
        "${PROJECT_SOURCE_DIR}/third_party/symcrypt/3rdparty/jitterentropy-library/jitterentropy.h")
    if(NOT EXISTS "${required}")
        message(FATAL_ERROR "Missing crypto submodules. Run: git submodule update --init --recursive")
    endif()
endforeach()
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${openssl_source}/VERSION.dat")
file(STRINGS "${openssl_source}/VERSION.dat" openssl_version REGEX "^(MAJOR|MINOR|PATCH)=")
if(NOT "${openssl_version}" STREQUAL "MAJOR=3;MINOR=5;PATCH=8")
    message(FATAL_ERROR "This build requires the pinned OpenSSL 3.5.8 submodule.")
endif()
set(openssl_prefix "${PROJECT_BINARY_DIR}/openssl")
set(openssl_install "${openssl_prefix}/install")
file(MAKE_DIRECTORY "${openssl_install}/include")
set(openssl_mode --release)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(openssl_mode --debug)
endif()
separate_arguments(openssl_flags NATIVE_COMMAND "${CMAKE_C_FLAGS}")
if(SYS_CERT_STORE_SANITIZERS)
    list(APPEND openssl_flags -fsanitize=address,undefined -fno-omit-frame-pointer)
endif()

ExternalProject_Add(scs-openssl-build
    PREFIX "${openssl_prefix}"
    SOURCE_DIR "${openssl_source}"
    BINARY_DIR "${openssl_prefix}/build"
    DOWNLOAD_COMMAND ""
    UPDATE_COMMAND ""
    CONFIGURE_COMMAND "${CMAKE_COMMAND}" -E env
        "CC=${CMAKE_C_COMPILER}" "AR=${CMAKE_AR}" "RANLIB=${CMAKE_RANLIB}"
        "${PERL_EXECUTABLE}" "${openssl_source}/Configure"
        ${openssl_mode} no-shared no-module no-dso no-tests -fPIC ${openssl_flags}
        "--prefix=${openssl_install}" "--openssldir=${openssl_install}/ssl" --libdir=lib
    BUILD_COMMAND "${SCS_MAKE}" -j2 build_libs
    BUILD_ALWAYS TRUE
    INSTALL_COMMAND "${SCS_MAKE}" install_dev
    BUILD_BYPRODUCTS "${openssl_install}/lib/libcrypto.a"
    LOG_CONFIGURE ON LOG_BUILD ON LOG_INSTALL ON
    LOG_OUTPUT_ON_FAILURE ON)

add_library(scs-openssl STATIC IMPORTED GLOBAL)
set_target_properties(scs-openssl PROPERTIES
    IMPORTED_LOCATION "${openssl_install}/lib/libcrypto.a"
    INTERFACE_INCLUDE_DIRECTORIES "${openssl_install}/include"
    INTERFACE_LINK_LIBRARIES "Threads::Threads;${CMAKE_DL_LIBS}")
add_dependencies(scs-openssl scs-openssl-build)

scs_patched_dependency(scossl d73b1e9ebf589f5c0098810e74e9556b2bef776a
    "${CMAKE_CURRENT_LIST_DIR}/patches/scossl-composite-mldsa.patch" scossl_source)
scs_patched_dependency(symcrypt 286762b7730e2b780678f5ab11fef2b1bad639e0
    "${CMAKE_CURRENT_LIST_DIR}/patches/symcrypt-curve-cache.patch" symcrypt_source)
set(symcrypt_build "${symcrypt_source}-build")
set(symcrypt_mode "${CMAKE_BUILD_TYPE}")
set(symcrypt_flags "${CMAKE_C_FLAGS}")
if(SYS_CERT_STORE_SANITIZERS)
    set(symcrypt_mode Sanitize)
    string(APPEND symcrypt_flags " -fno-omit-frame-pointer")
endif()
execute_process(COMMAND "${GIT_EXECUTABLE}" -C "${PROJECT_SOURCE_DIR}/third_party/symcrypt"
    show -s --format=%cI HEAD OUTPUT_VARIABLE symcrypt_timestamp
    OUTPUT_STRIP_TRAILING_WHITESPACE COMMAND_ERROR_IS_FATAL ANY)
set(symcrypt_environment
    "SYMCRYPT_BRANCH=sys-cert-store-static"
    "SYMCRYPT_COMMIT_HASH=286762b7730e2b780678f5ab11fef2b1bad639e0+scs"
    "SYMCRYPT_COMMIT_TIMESTAMP=${symcrypt_timestamp}")
ExternalProject_Add(scs-symcrypt-build
    SOURCE_DIR "${symcrypt_source}"
    BINARY_DIR "${symcrypt_build}"
    DOWNLOAD_COMMAND "" UPDATE_COMMAND ""
    CONFIGURE_COMMAND "${CMAKE_COMMAND}" -E env ${symcrypt_environment}
        "${CMAKE_COMMAND}" -S <SOURCE_DIR> -B <BINARY_DIR> "-G${CMAKE_GENERATOR}"
        "-DCMAKE_BUILD_TYPE=${symcrypt_mode}"
        "-DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}" "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
        "-DPython3_EXECUTABLE=${Python3_EXECUTABLE}" "-DCMAKE_C_FLAGS=${symcrypt_flags}"
        -DSYMCRYPT_BUILD_MODULES=OFF -DSYMCRYPT_PIC=ON
    BUILD_COMMAND "${CMAKE_COMMAND}" -E env ${symcrypt_environment}
        "${CMAKE_COMMAND}" --build <BINARY_DIR> --parallel 2
        --target symcrypt_posixusermode
    INSTALL_COMMAND "" BUILD_ALWAYS TRUE
    BUILD_BYPRODUCTS "${symcrypt_build}/lib/libsymcrypt_posixusermode.a"
        "${symcrypt_build}/lib/libsymcrypt_common.a" "${symcrypt_build}/lib/libsymcrypt_mlkem.a"
    LOG_CONFIGURE ON LOG_BUILD ON LOG_OUTPUT_ON_FAILURE ON)
foreach(component posixusermode common mlkem)
    add_library(scs-symcrypt-${component} STATIC IMPORTED GLOBAL)
    set_target_properties(scs-symcrypt-${component} PROPERTIES
        IMPORTED_LOCATION "${symcrypt_build}/lib/libsymcrypt_${component}.a")
    add_dependencies(scs-symcrypt-${component} scs-symcrypt-build)
endforeach()

# The entropy timing source must retain upstream's -O0 and wrapping arithmetic.
set(jitter_source "${PROJECT_SOURCE_DIR}/third_party/symcrypt/3rdparty/jitterentropy-library")
file(GLOB jitter_sources CONFIGURE_DEPENDS "${jitter_source}/src/*.c")
add_library(scs-jitter STATIC ${jitter_sources})
set_target_properties(scs-jitter PROPERTIES POSITION_INDEPENDENT_CODE ON C_STANDARD 11)
target_include_directories(scs-jitter PRIVATE "${jitter_source}" "${jitter_source}/src")
target_compile_options(scs-jitter PRIVATE -O0 -fwrapv -fstack-protector-strong)

set(symcrypt_runtime "${symcrypt_source}/modules/posix/common")
add_library(scs-symcrypt-runtime STATIC "${PROJECT_SOURCE_DIR}/src/symcrypt-static.c"
    "${symcrypt_runtime}/rng.c" "${symcrypt_runtime}/callbacks_pthread.c"
    "${symcrypt_runtime}/optional/rngsecureurandom.c"
    "${symcrypt_runtime}/optional/rngforkdetection.c"
    "${symcrypt_runtime}/optional/rngfipsjitter.c")
set_target_properties(scs-symcrypt-runtime PROPERTIES POSITION_INDEPENDENT_CODE ON C_STANDARD 11)
target_include_directories(scs-symcrypt-runtime PRIVATE "${symcrypt_source}/inc"
    "${symcrypt_source}" "${symcrypt_runtime}" "${symcrypt_build}/inc" "${jitter_source}")
target_compile_definitions(scs-symcrypt-runtime PRIVATE
    SYMCRYPT_MODULE_DO_FIPS_SELFTESTS=1 SYMCRYPT_MODULE_USE_FIPS_ENTROPY=1)
target_compile_options(scs-symcrypt-runtime PRIVATE -Wno-multichar)
target_link_libraries(scs-symcrypt-runtime PUBLIC
    scs-symcrypt-posixusermode scs-symcrypt-common scs-symcrypt-mlkem
    scs-jitter Threads::Threads atomic)
target_link_options(scs-symcrypt-runtime INTERFACE "LINKER:-z,noexecstack")

# Compile the pinned provider and common sources, not upstream's shared-module targets.
file(GLOB_RECURSE scossl_sources CONFIGURE_DEPENDS "${scossl_source}/SymCryptProvider/src/*.c")
file(GLOB scossl_common_sources CONFIGURE_DEPENDS "${scossl_source}/ScosslCommon/src/*.c")
set(provider_base "${scossl_source}/SymCryptProvider/src/p_scossl_base.c")
file(READ "${provider_base}" provider_code)
string(REPLACE "fips=yes" "fips=no" provider_code "${provider_code}")
file(WRITE "${PROJECT_BINARY_DIR}/p_scossl_base.c" "${provider_code}")
list(REMOVE_ITEM scossl_sources "${provider_base}")
set(SymCrypt-OpenSSL_VERSION "1.10.0-scs-static")
set(SYMCRYPT_MINIMUM_MAJOR 103)
set(SYMCRYPT_MINIMUM_MINOR 12)
configure_file("${scossl_source}/SymCryptProvider/inc/p_scossl_base.h.in"
    "${PROJECT_BINARY_DIR}/scossl-inc/p_scossl_base.h" @ONLY)
add_library(scs-scossl STATIC ${scossl_sources} ${scossl_common_sources}
    "${PROJECT_BINARY_DIR}/p_scossl_base.c")
set_target_properties(scs-scossl PROPERTIES POSITION_INDEPENDENT_CODE ON C_STANDARD 11)
target_include_directories(scs-scossl PRIVATE "${PROJECT_BINARY_DIR}/scossl-inc"
    "${scossl_source}/SymCryptProvider/inc" "${scossl_source}/SymCryptProvider/src"
    "${scossl_source}/ScosslCommon/inc" "${symcrypt_source}/inc")
target_compile_definitions(scs-scossl PRIVATE OSSL_provider_init=scs_symcrypt_provider_init
    SymCryptModuleInit=scs_symcrypt_static_init)
target_compile_options(scs-scossl PRIVATE -Wno-deprecated-declarations -Wno-multichar)
target_link_libraries(scs-scossl PUBLIC scs-symcrypt-runtime scs-openssl)

add_library(scs-crypto STATIC "${PROJECT_SOURCE_DIR}/src/crypto.cpp")
set_target_properties(scs-crypto PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_features(scs-crypto PUBLIC cxx_std_20)
target_include_directories(scs-crypto PUBLIC "${PROJECT_SOURCE_DIR}/src")
target_link_libraries(scs-crypto PUBLIC scs-scossl scs-openssl)
if(SYS_CERT_STORE_SANITIZERS)
    foreach(target scs-scossl scs-symcrypt-runtime scs-crypto)
        target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    endforeach()
endif()
install(FILES "${openssl_source}/LICENSE.txt" DESTINATION "${CMAKE_INSTALL_DATADIR}/sys-cert-store/licenses/openssl")
install(FILES "${scossl_source}/LICENSE" DESTINATION "${CMAKE_INSTALL_DATADIR}/sys-cert-store/licenses/scossl")
install(FILES "${symcrypt_source}/LICENSE.txt" DESTINATION "${CMAKE_INSTALL_DATADIR}/sys-cert-store/licenses/symcrypt")
install(FILES "${jitter_source}/LICENSE" "${jitter_source}/LICENSE.bsd"
    DESTINATION "${CMAKE_INSTALL_DATADIR}/sys-cert-store/licenses/jitterentropy")
