cmake_minimum_required(VERSION 3.16)
project(ngx_anytls_unit C)

# Deterministic unit tests for the standalone parse/validate layer,
# sharing the fuzz build's nginx-header + stub approach.
#
# Usage:
#   cmake -B build-unit -DNGX_SRC=/path/to/nginx-src tests/c
#   cmake --build build-unit
#   ctest --test-dir build-unit --output-on-failure

set(NGX_SRC "" CACHE PATH "nginx source tree containing objs/ngx_auto_config.h")
set(MODULE_SRC "${CMAKE_CURRENT_LIST_DIR}/../../src" CACHE PATH "ngx_anytls src dir")
set(FUZZ_STUB "${CMAKE_CURRENT_LIST_DIR}/../../fuzz/stub/ngx_stub.c")
set(NGX_ANYTLS_UNIT_SANITIZE OFF CACHE BOOL "build with ASan+UBSan")

if(NGX_ANYTLS_UNIT_SANITIZE)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -O1 -g)
    add_link_options(-fsanitize=address,undefined)
endif()

if(NOT NGX_SRC)
    message(FATAL_ERROR "set -DNGX_SRC=/path/to/nginx-src")
endif()

set(NGX_INCLUDES
    "${NGX_SRC}/objs"
    "${NGX_SRC}/src/core"
    "${NGX_SRC}/src/event"
    "${NGX_SRC}/src/event/quic"
    "${NGX_SRC}/src/os/unix"
    "${NGX_SRC}/src/stream"
    "${MODULE_SRC}"
)

set(NGX_ANYTLS_UNIT_SRCS
    "${MODULE_SRC}/ngx_anytls_protocol.c"
    "${MODULE_SRC}/ngx_anytls_socksaddr.c"
    "${MODULE_SRC}/ngx_anytls_padding.c"
    "${MODULE_SRC}/ngx_anytls_auth.c"
    "${MODULE_SRC}/ngx_anytls_client_buffer.c"
    "${FUZZ_STUB}"
)

foreach(name frame settings padding socksaddr auth client_buffer)
    add_executable(test_${name} test_${name}.c ${NGX_ANYTLS_UNIT_SRCS})
    target_include_directories(test_${name} PRIVATE ${NGX_INCLUDES})
    target_link_libraries(test_${name} PRIVATE crypto)
    add_test(NAME test_${name} COMMAND test_${name})
endforeach()

add_executable(test_cache_budget test_cache_budget.c)
target_include_directories(test_cache_budget PRIVATE "${MODULE_SRC}")
add_test(NAME test_cache_budget COMMAND test_cache_budget)

add_executable(test_stream_index test_stream_index.c)
target_include_directories(test_stream_index PRIVATE "${MODULE_SRC}")
add_test(NAME test_stream_index COMMAND test_stream_index)

enable_testing()
