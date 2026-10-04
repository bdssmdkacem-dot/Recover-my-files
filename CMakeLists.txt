cmake_minimum_required(VERSION 3.24)
project(RecoverMyFiles LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT WIN32)
  message(FATAL_ERROR "Recover My Files currently targets Windows.")
endif()
add_executable(Recovery WIN32
  src/main.cpp
  src/recovery_engine.cpp
)
target_include_directories(Recovery PRIVATE src)
target_compile_definitions(Recovery PRIVATE UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN)
target_link_libraries(Recovery PRIVATE user32 comctl32 shell32 ole32 advapi32)
if(MSVC)
  target_compile_options(Recovery PRIVATE /W4 /EHsc /utf-8)
  target_link_options(Recovery PRIVATE /SUBSYSTEM:WINDOWS)
endif()
