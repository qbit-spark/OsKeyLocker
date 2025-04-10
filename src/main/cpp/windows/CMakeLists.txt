cmake_minimum_required(VERSION 3.10)
project(WindowsDPAPI)

set(CMAKE_CXX_STANDARD 11)

# Set JDK path (escape spaces)
set(JAVA_HOME "C:/Program Files/Java/jdk-22")

# JNI header includes
include_directories(
        "${JAVA_HOME}/include"
        "${JAVA_HOME}/include/win32"
        "${CMAKE_CURRENT_SOURCE_DIR}"
)

# Build shared library
add_library(WindowsDPAPI SHARED WindowsDPAPI.cpp)

# Link Windows Crypt32
target_link_libraries(WindowsDPAPI Crypt32)

# Optional: Set DLL output path
set_target_properties(WindowsDPAPI PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
