cmake_minimum_required(VERSION 3.20)
project(sys-cert-store VERSION 0.1.0 LANGUAGES CXX)

include(GNUInstallDirs)
include(CTest)
find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)
find_package(SQLite3 3.31 REQUIRED)
find_package(Threads REQUIRED)

option(SYS_CERT_STORE_SANITIZERS "Enable address and undefined behavior sanitizers" OFF)
add_library(sys-cert-store SHARED src/store.cpp src/native.cpp)
add_library(sys-cert-store::sys-cert-store ALIAS sys-cert-store)
target_compile_features(sys-cert-store PUBLIC cxx_std_20)
target_include_directories(sys-cert-store PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_link_libraries(sys-cert-store PRIVATE OpenSSL::Crypto SQLite::SQLite3 Threads::Threads)
target_compile_options(sys-cert-store PRIVATE -Wall -Wextra -Wpedantic -Werror)
set_target_properties(sys-cert-store PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION 0)
if(SYS_CERT_STORE_SANITIZERS)
    target_compile_options(sys-cert-store PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(sys-cert-store PUBLIC -fsanitize=address,undefined)
endif()

add_executable(list-certificates examples/list-certificates.cpp)
target_link_libraries(list-certificates PRIVATE sys-cert-store)
add_subdirectory(tools)

if(BUILD_TESTING)
    add_executable(store-tests tests/store-tests.cpp)
    target_link_libraries(store-tests PRIVATE sys-cert-store OpenSSL::Crypto SQLite::SQLite3 Threads::Threads)
    target_compile_options(store-tests PRIVATE -Wall -Wextra -Wpedantic -Werror)
    add_test(NAME store-tests COMMAND store-tests)
    add_test(NAME certutil-tests COMMAND store-tests --certutil $<TARGET_FILE:certutil>)
endif()

install(TARGETS sys-cert-store EXPORT sys-cert-store-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT sys-cert-store-targets NAMESPACE sys-cert-store::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/sys-cert-store)
include(CMakePackageConfigHelpers)
configure_package_config_file(cmake/sys-cert-store-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/sys-cert-store-config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/sys-cert-store)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/sys-cert-store-config-version.cmake
    COMPATIBILITY SameMajorVersion)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/sys-cert-store-config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/sys-cert-store-config-version.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/sys-cert-store)
