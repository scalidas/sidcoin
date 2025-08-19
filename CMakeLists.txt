# CMakeList.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
cmake_minimum_required (VERSION 3.8)

# Enable Hot Reload for MSVC compilers if supported.
if (POLICY CMP0141)
  cmake_policy(SET CMP0141 NEW)
  set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<IF:$<AND:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>,$<$<CONFIG:Debug,RelWithDebInfo>:EditAndContinue>,$<$<CONFIG:Debug,RelWithDebInfo>:ProgramDatabase>>")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)


project ("sidcoin")

find_package(OpenSSL REQUIRED)

set(SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src")
file(GLOB_RECURSE ALL_SOURCE_FILES
    CONFIGURE_DEPENDS
    "${SOURCE_DIR}/*.cpp"
)
add_executable(sidcoin ${ALL_SOURCE_FILES} "src/mining/mining.cpp" "include/mining/mining.h")

target_link_libraries(sidcoin PUBLIC OpenSSL::SSL OpenSSL::Crypto)

target_include_directories(sidcoin PUBLIC ${CMAKE_SOURCE_DIR}/include )
target_include_directories(sidcoin PUBLIC ${CMAKE_SOURCE_DIR}/external )