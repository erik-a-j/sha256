cmake_minimum_required(VERSION 3.30)

project(sha256 LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(SHA256_SOURCES sha256.c)

add_library(sha256 STATIC ${SHA256_SOURCES})
target_compile_options(sha256 PRIVATE -Wall -Wextra -Wpedantic -Werror)

add_executable(main main.c)
target_link_libraries(main PRIVATE sha256)

foreach(SRC ${SHA256_SOURCES})
    get_filename_component(BASE ${SRC} NAME_WE)
    add_custom_command(
        OUTPUT ${BASE}.s
        COMMAND ${CMAKE_C_COMPILER}
            -S ${CMAKE_CURRENT_SOURCE_DIR}/${SRC}
            -o ${CMAKE_CURRENT_BINARY_DIR}/${BASE}.s
            -O2 -march=native -masm=intel -fverbose-asm
            -std=c${CMAKE_C_STANDARD}
            DEPENDS ${SRC}
        VERBATIM
    )
    list(APPEND ASM_OUTPUTS ${CMAKE_CURRENT_BINARY_DIR}/${BASE}.s)
endforeach()

add_custom_target(asm DEPENDS ${ASM_OUTPUTS})