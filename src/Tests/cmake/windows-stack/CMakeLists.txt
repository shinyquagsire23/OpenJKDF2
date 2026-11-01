cmake_minimum_required(VERSION 3.16)
project(OpenJKDF2WindowsStackProbe C)
add_executable(windows_stack_probe ../../windows_stack_probe.c)
target_compile_options(windows_stack_probe PRIVATE -Wall -Wextra -Werror)
