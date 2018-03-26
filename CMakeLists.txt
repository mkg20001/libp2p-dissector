# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

include(WiresharkPlugin)
include(${CMAKE_CURRENT_SOURCE_DIR}/protobuf.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/protobuf-c.cmake)

# Plugin name and version info (major minor micro extra)
set_module_info(libp2p 0 0 1 0)

set(DISSECTOR_SRC
		addr-pair.c
		length-prefixed.c
		proto-util.c
		packet-multistream.c
		packet-secio.c
		packet-yamux.c
		packet-spdy.c
		protos/secio.pb-c.c
		protos/key.pb-c.c
)

set(PLUGIN_FILES_REAL
	plugin.c
	${DISSECTOR_SRC}
)

set(PLUGIN_FILES
	${PLUGIN_FILES_REAL}
	${PC_SOURCES}
)

set_source_files_properties(
	${PLUGIN_FILES_REAL}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

file(GLOB PROTOS "${CMAKE_CURRENT_SOURCE_DIR}/protos/*.proto")

macro(compile_proto_file filename)
	get_filename_component(basename ${filename} NAME_WE)
	add_custom_command(
			OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/protos/${basename}.pb-c.c ${CMAKE_CURRENT_SOURCE_DIR}/protos/${basename}.pb-c.h
			DEPENDS protoc ${CMAKE_CURRENT_SOURCE_DIR}/protos/${basename}.proto
			COMMAND protoc ${CMAKE_CURRENT_SOURCE_DIR}/protos/${basename}.proto
			--proto_path=${CMAKE_CURRENT_SOURCE_DIR}/protos
			--plugin=$<TARGET_FILE:protoc-gen-c>
			--c_out=${CMAKE_CURRENT_SOURCE_DIR}/protos
	)
	add_custom_target(compileProto${basename}
			DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/protos/${basename}.pb-c.c ${CMAKE_CURRENT_SOURCE_DIR}/protos/${basename}.pb-c.h)
	add_dependencies(libp2p compileProto${basename})
endmacro(compile_proto_file)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

register_plugin_files(plugin.c
	plugin
	${DISSECTOR_SRC}
)

add_plugin_library(libp2p epan)
foreach(proto_file ${PROTOS})
	compile_proto_file(${proto_file})
endforeach(proto_file)

target_link_libraries(libp2p epan)
target_link_libraries(libp2p libprotobuf)
target_link_libraries(libp2p protobuf-c)

install_plugin(libp2p epan)

file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
CHECKAPI(
	NAME
	  libp2p
	SWITCHES
	  -g abort -g termoutput -build
	SOURCES
	  ${DISSECTOR_SRC}
	  ${DISSECTOR_HEADERS}
)

#
# Editor modelines  -  http://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 8
# tab-width: 8
# indent-tabs-mode: t
# End:
#
# vi: set shiftwidth=8 tabstop=8 noexpandtab:
# :indentSize=8:tabSize=8:noTabs=false:
#
