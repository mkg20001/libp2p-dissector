/* proto-util.c
 * Helpers for protobuf things
 * Copyright 2018, Maciej Krüger <mkg20001@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <epan/packet.h>   /* Should be first Wireshark include (other than config.h) */
#include "proto-util.h"

static void *
wmem_pbuf_alloc(void *allocator_data, size_t size)
{
  return wmem_alloc((wmem_allocator_t *)allocator_data, size);
}

static void
wmem_pbuf_free(void *allocator_data, void *data)
{
  return wmem_free((wmem_allocator_t *)allocator_data, data);
}

// This one is a private func from tvbuff.c. we need it for pbufs so let's c&p it here
guint8 *
tvb_get_raw_string(wmem_allocator_t *scope, tvbuff_t *tvb, const gint offset, const gint length)
{
  guint8 *strbuf;
  gint    abs_length = length;

  DISSECTOR_ASSERT(offset     >=  0);
  DISSECTOR_ASSERT(abs_length >= -1);

  if (abs_length < 0)
    abs_length = tvb_captured_length(tvb) - offset;

  tvb_ensure_bytes_exist(tvb, offset, abs_length);
  strbuf = (guint8 *)wmem_alloc(scope, abs_length + 1);
  tvb_memcpy(tvb, strbuf, offset, abs_length);
  strbuf[abs_length] = '\0';
  return strbuf;
}

ProtobufCAllocator * pbuf_alloc(wmem_allocator_t* alloc) {
  ProtobufCAllocator *al = wmem_new(alloc, ProtobufCAllocator);
  al->allocator_data = (void *)alloc;
  al->alloc = &wmem_pbuf_alloc;
  al->free = &wmem_pbuf_free;
  return al;
}
