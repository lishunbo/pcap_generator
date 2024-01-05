cmake_minimum_required(VERSION 3.16)

project(pcap_generator)

add_library(libpcap STATIC IMPORTED)
set_target_properties(
  libpcap PROPERTIES IMPORTED_LOCATION
                     ${CMAKE_SOURCE_DIR}/libpcap-1.10.4/libpcap.a)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/libpcap-1.10.4)

add_executable(pcap_generator main.cc helper.cc)
target_link_libraries(pcap_generator libpcap)
target_compile_features(pcap_generator PUBLIC cxx_std_17)
# target_compile_definitions(${TARGETEXEC} PUBLIC ENABLE_AUDIO ENABLE_VIDEO)
