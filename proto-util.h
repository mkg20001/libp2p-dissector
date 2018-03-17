#include <plugins/epan/libp2p/protobuf-c/protobuf-c/protobuf-c.h>

ProtobufCAllocator * pbuf_alloc(wmem_allocator_t* alloc);
guint8 *
tvb_get_raw_string(wmem_allocator_t *scope, tvbuff_t *tvb, const gint offset, const gint length);