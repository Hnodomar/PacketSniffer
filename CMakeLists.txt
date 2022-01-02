cmake_minimum_required(VERSION 3.16)

project(PacketSniffer)

set(src_dir "${CMAKE_SOURCE_DIR}/src")
set(inc_dir "${CMAKE_SOURCE_DIR}/inc")
file(GLOB pkts_src CONFIGURE_DEPENDS
    "${src_dir}/main.cpp"
)

add_executable(packet_sniffer
    ${pkts_src}
)
