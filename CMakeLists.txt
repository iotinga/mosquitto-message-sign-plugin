cmake_minimum_required(VERSION 3.22)

project(mosquitto-message-sign-plugin VERSION 1.0)

option(ENABLE_TESTS "Enable compilation of tests" OFF)

# Set the output directory for the compiled plugin
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(MOSQUITTO REQUIRED libmosquitto)
pkg_check_modules(LIBCBOR REQUIRED libcbor)
pkg_check_modules(LIBSODIUM REQUIRED libsodium)
pkg_check_modules(LIBPQ REQUIRED libpq)

# Specify the include directories
include_directories(${MOSQUITTO_INCLUDE_DIRS} ${LIBCBOR_INCLUDE_DIRS} ${LIBSODIUM_INCLUDE_DIRS} ${LIBPQ_INCLUDE_DIRS} src)

# Specify the source files
file(GLOB SOURCES "src/*.c")

# Create the shared library (plugin)
add_library(${PROJECT_NAME} SHARED ${SOURCES})

# Link the required libraries
target_link_libraries(${PROJECT_NAME} ${MOSQUITTO_LINK_LIBRARIES} ${LIBCBOR_LINK_LIBRARIES} ${LIBSODIUM_LINK_LIBRARIES} ${LIBPQ_LINK_LIBRARIES})

# Set the shared library version properties
set_target_properties(${PROJECT_NAME} PROPERTIES
    PREFIX ""  # Remove the 'lib' prefix
    SUFFIX ".so"  # Ensure the plugin has the .so extension
    POSITION_INDEPENDENT_CODE ON # Needed for shared libraries
)

# Install the library
install(TARGETS ${PROJECT_NAME} 
    LIBRARY DESTINATION lib
)

# Set CMake to use RPATH
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)


if (ENABLE_TESTS)
    enable_testing()
    add_compile_options("-g")

    # Add the tests subdirectory
    add_subdirectory(test)
endif()