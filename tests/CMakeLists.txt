find_package(Catch2 REQUIRED)

add_executable(unit_tests
    ${CMAKE_CURRENT_SOURCE_DIR}/main.cpp
)

target_link_libraries(unit_tests
    Catch2::Catch2
)

include(CTest)
include(Catch)
catch_discover_tests(unit_tests)
