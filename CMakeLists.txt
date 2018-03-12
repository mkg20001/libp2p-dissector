# CMakeLists.txt
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

include(WiresharkPlugin)

# Plugin name and version info (major minor micro extra)
set_module_info(libp2p 0 0 1 0)

set(DISSECTOR_SRC
		length-prefixed.c
		packet-multistream.c
		packet-secio.c
)

set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
)

include(${CMAKE_CURRENT_SOURCE_DIR}/protobuf.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/protobuf-c.cmake)

set_source_files_properties(
	${PLUGIN_FILES}
	PROPERTIES
	COMPILE_FLAGS "${WERROR_COMMON_FLAGS}"
)

file(GLOB PROTOS "${CMAKE_CURRENT_SOURCE_DIR}/protos/*.proto")

macro(compile_proto_file filename)
	get_filename_component(basename ${filename} NAME_WE)
	add_custom_command(
#			OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/protos/${basename}.pb-c.c ${CMAKE_CURRENT_SOURCE_DIR}/protos/${basename}.pb-c.h
			DEPENDS protoc ${CMAKE_CURRENT_SOURCE_DIR}/protos/${basename}.proto
			TARGET compileProto PRE_BUILD
			COMMAND protoc ${CMAKE_CURRENT_SOURCE_DIR}/protos/${basename}.proto
			--proto_path=${CMAKE_CURRENT_SOURCE_DIR}/protos
			--plugin=$<TARGET_FILE:protoc-gen-c>
			--c_out=${CMAKE_CURRENT_SOURCE_DIR}/protos
	)
endmacro(compile_proto_file)

add_custom_target(compileProto)
foreach(proto_file ${PROTOS})
	compile_proto_file(${proto_file})
endforeach(proto_file)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

register_plugin_files(plugin.c
	plugin
	${DISSECTOR_SRC}
)

add_plugin_library(libp2p epan)
add_dependencies(libp2p compileProto)

target_link_libraries(libp2p epan)

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
