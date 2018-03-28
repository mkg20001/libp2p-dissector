'use strict'

const inProto = process.argv[2]
const fs = require('fs')
const content = fs.readFileSync(inProto).toString()
const pschema = require('protocol-buffers-schema')
const s = pschema(content)

const redef = ['protobuf_c_version', 'protobuf_c_version_number', 'protobuf_c_buffer_simple_append', 'protobuf_c_message_get_packed_size', 'protobuf_c_message_pack', 'protobuf_c_message_pack_to_buffer', 'protobuf_c_message_unpack', 'protobuf_c_message_free_unpacked', 'protobuf_c_message_init', 'protobuf_c_message_check', 'protobuf_c_service_invoke_internal', 'protobuf_c_service_generated_init', 'protobuf_c_service_destroy', 'protobuf_c_enum_descriptor_get_value_by_name', 'protobuf_c_enum_descriptor_get_value', 'protobuf_c_message_descriptor_get_field_by_name', 'protobuf_c_message_descriptor_get_field', 'protobuf_c_service_descriptor_get_method_by_name']

function lcase (s) {
  s = s.substr(0, 1).toLowerCase() + s.substr(1)
  s = s.replace(/[A-Z]/g, a => '_' + a.toLowerCase())
  return s
}

function getPbufCode () { // just don't touch it. plz.
  let d = fs.readFileSync(MAIN + '/protobuf-c/protobuf-c/protobuf-c.c').toString().replace('const char protobuf_c_empty_string[] = "";', '').replace('; \\\n                }', ';}')
  redef.forEach(v => {
    let re = new RegExp('^.*\\n.*' + v + '.+(\\n.+)*\\n{', 'm')
    let s = d.replace(re, () => 'ȣ').split('ȣ')
    // console.log(v, re, s.length)
    s[1] = s[1].replace(/^ *\} *$/m, () => 'ȣ').split('ȣ').slice(1).join('}')
    d = s.join('\n')
  })
  return d
}

const helper = `
size_t field_packed(const ProtobufCFieldDescriptor *field, const void *member, const void *qmember)
{
	unsigned i;
	size_t rv = 0;

	if (field->label == PROTOBUF_C_LABEL_REQUIRED) {
		rv += required_field_get_packed_size(field, member);
	} else if ((field->label == PROTOBUF_C_LABEL_OPTIONAL ||
		    field->label == PROTOBUF_C_LABEL_NONE) &&
		   (0 != (field->flags & PROTOBUF_C_FIELD_FLAG_ONEOF))) {
		rv += oneof_field_get_packed_size(
			field,
			*(const uint32_t *) qmember,
			member
		);
	} else if (field->label == PROTOBUF_C_LABEL_OPTIONAL) {
		rv += optional_field_get_packed_size(
			field,
			*(protobuf_c_boolean *) qmember,
			member
		);
	} else if (field->label == PROTOBUF_C_LABEL_NONE) {
		rv += unlabeled_field_get_packed_size(
			field,
			member
		);
	} else {
		rv += repeated_field_get_packed_size(
			field,
			*(const size_t *) qmember,
			member
		);
	}
	return rv;
}
`

const helperHead = `
#include<protobuf-c.h>
size_t field_packed(const ProtobufCFieldDescriptor *field, const void *member, const void *qmember);
`

function con (d) {
  return d.map(d => [d.file, d.head]).reduce((a, b) => {
    a[0] += '\n\n' + b[0]
    a[1] += '\n\n' + b[1]
    return a
  }, ['', ''])
}

function buildExpr (msg, f, isSetExpr, getExpr) {
  let _h_expr = 'count->has_' + f.l
  let _o_expr = 'count->off_' + f.l
  let _l_expr = 'count->len_' + f.l

  let qexpr = 'NULL'
  if (!f.required) qexpr = `(const void *)&count->has_${f.l}`
  if (f.repeated) qexpr = `(const void *)&msg->n_${f.l}`

  let getLenExpr = `field_packed(desc_${f.l}, (const void *) ${getExpr}, ${qexpr})`
  let o = []
  o.push(`const ProtobufCFieldDescriptor* desc_${f.l} = ${msg.l}__descriptor.fields + ${f.tag - 1};`)
  if (!f.required) {
    o.push(`${_h_expr} = ${isSetExpr};`)
    o.push(`if (${isSetExpr}) {`)
  }
  o.push(`  ${_o_expr} = offset;`)
  o.push(`  ${_l_expr} = ${getLenExpr};`)
  o.push(`  offset += ${_l_expr};`)
  if (!f.required) {
    o.push(`} else {`)
    o.push(`  ${_l_expr} = 0;`)
    o.push(`  ${_o_expr} = 0;`)
    o.push(`}`)
  }
  return o
}

function processMessage (msg, path) {
  let Path = path || []
  Path.push()
  let structBegin = `typedef struct _${msg.name}Count {`
  let structEnd = `\n} ${msg.name}Count;`

  let fncDef = `${msg.name}Count * count${msg.name}(size_t offset, ${msg.name}* msg)`
  let fncBegin = `${fncDef} {`
  let fncEnd = `\n    return count;\n}`

  let struct = ['']
  let fnc = ['', `${msg.name}Count* count = wmem_new(wmem_packet_scope(), ${msg.name}Count);`]

  let ad = {
    file: '',
    head: ''
  }

  msg.l = lcase(msg.name)
  msg.fields.forEach(f => {
    f.l = lcase(f.name)
    let expr = 'msg->' + f.l
    let name = f.l
    let getExpr = 'msg->' + f.l
    if (!f.required) struct.push(`gboolean has_${name};`)
    struct.push(`size_t off_${name};`)
    struct.push(`size_t len_${name};`)
    switch (f.type) {
      case 'string':
        fnc.push(...buildExpr(msg, f, `${expr} != NULL`, '&' + getExpr))
        break
      case 'bytes':
        fnc.push(...buildExpr(msg, f, `msg->has_` + f.l, '&' + getExpr))
        break
    }
  })

  return {
    file: fncBegin + fnc.join('\n    ') + fncEnd + ad.file,
    head: [structBegin + struct.join('\n    ') + structEnd, fncDef + ';', ad.head].join('\n')
  }
}

const path = require('path')
const MAIN = path.dirname(__dirname)

function processSchema (s, name) {
  let [file, head] = con(s.messages.map(s => processMessage(s)))
  file = [`#include <${name}.offset.h>`, '', file].join('\n')
  head = ['#include <epan/packet.h>', '#include <_.offset.h>', `#include <protos/${name}.pb-c.h>`, head].join('\n\n')
  fs.writeFileSync(`${MAIN}/_.offset.c`, Buffer.from(['#include<_.offset.h>', getPbufCode(), helper].join('\n\n')))
  fs.writeFileSync(`${MAIN}/_.offset.h`, Buffer.from(helperHead))
  fs.writeFileSync(`${MAIN}/${name}.offset.c`, Buffer.from(file))
  fs.writeFileSync(`${MAIN}/${name}.offset.h`, Buffer.from(head))
}

processSchema(s, path.basename(inProto).split('.').shift())
