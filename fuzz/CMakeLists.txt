cmake_minimum_required(VERSION 3.16)
project(ngx_anytls_fuzz C)

# Local libFuzzer build for ngx_anytls parsing entry points.
#
# Usage:
#   cmake -B build-fuzz \
#       -DCMAKE_C_COMPILER=clang \
#       -DNGX_SRC=/path/to/nginx-src \
#       fuzz
#   cmake --build build-fuzz
#   Run raw fuzzing into fuzz/local/ (git-ignored), then merge the
#   coverage-minimal result back into the committed corpus:
#     mkdir -p fuzz/local/frame_parse
#     ./build-fuzz/fuzz/fuzz_frame_parse fuzz/local/frame_parse/ -max_total_time=300
#     ./build-fuzz/fuzz/fuzz_frame_parse -merge=1 fuzz/corpus/frame_parse fuzz/local/frame_parse

if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "fuzz build requires LLVM Clang (libFuzzer)")
endif()

set(NGX_SRC "" CACHE PATH "nginx source tree containing objs/ngx_auto_config.h")
set(MODULE_SRC "${CMAKE_CURRENT_LIST_DIR}/../src" CACHE PATH "ngx_anytls src dir")

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

set(FUZZ_FLAGS
    -fsanitize=fuzzer,address,undefined
    -fno-omit-frame-pointer
    -O1 -g
)
set(FUZZ_LINK_FLAGS
    -fsanitize=fuzzer,address,undefined
)

function(add_anytls_fuzz name)
    add_executable(fuzz_${name} ${ARGN})
    target_include_directories(fuzz_${name} PRIVATE ${NGX_INCLUDES})
    target_compile_options(fuzz_${name} PRIVATE ${FUZZ_FLAGS})
    target_link_options(fuzz_${name} PRIVATE ${FUZZ_LINK_FLAGS})
    target_link_libraries(fuzz_${name} PRIVATE crypto)
endfunction()

set(NGX_ANYTLS_FUZZ_SRCS
    "${MODULE_SRC}/ngx_anytls_protocol.c"
    "${MODULE_SRC}/ngx_anytls_socksaddr.c"
    "${MODULE_SRC}/ngx_anytls_padding.c"
    "${MODULE_SRC}/ngx_anytls_auth.c"
)

add_anytls_fuzz(frame_parse
    targets/fuzz_frame_parse.c
    ${NGX_ANYTLS_FUZZ_SRCS}
    stub/ngx_stub.c
)

add_anytls_fuzz(settings_parse
    targets/fuzz_settings_parse.c
    ${NGX_ANYTLS_FUZZ_SRCS}
    stub/ngx_stub.c
)

add_anytls_fuzz(padding_validate
    targets/fuzz_padding_validate.c
    ${NGX_ANYTLS_FUZZ_SRCS}
    stub/ngx_stub.c
)

add_anytls_fuzz(uot_packet
    targets/fuzz_uot_packet.c
    ${NGX_ANYTLS_FUZZ_SRCS}
    stub/ngx_stub.c
)

add_anytls_fuzz(auth
    targets/fuzz_auth.c
    ${NGX_ANYTLS_FUZZ_SRCS}
    stub/ngx_stub.c
)
