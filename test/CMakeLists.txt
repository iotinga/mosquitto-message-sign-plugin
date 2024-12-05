# Find CMocka
find_package(CMocka REQUIRED)

set(TEST_SOURCES 
    ${CMAKE_CURRENT_SOURCE_DIR}/../src/utils.c
)

set(TEST_INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/../src
    ${LIBSODIUM_INCLUDE_DIRS}
    ${LIBCBOR_INCLUDE_DIRS}
    ${CMOCKA_INCLUDE_DIRS}
)

set(TEST_LINK_LIBRARIES
    ${LIBSODIUM_LIBRARIES}
    ${LIBCBOR_LIBRARIES}
    ${CMOCKA_LIBRARIES}
)

macro(make_test test_name)
    # Add the test executable
    add_executable(${test_name} ${test_name}.c)

    # Include directories
    target_include_directories(${test_name} PRIVATE ${TEST_INCLUDE_DIRS})

    # Sources
    target_sources(${test_name} PUBLIC ${TEST_SOURCES})

    # Link libraries
    target_link_libraries(${test_name} ${TEST_LINK_LIBRARIES})

    # Add the test to CTest
    add_test(NAME ${test_name} COMMAND ${test_name})
endmacro()

make_test(test_utils)

