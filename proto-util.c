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

ProtobufCAllocator * pbuf_alloc(wmem_allocator_t* alloc) {
  ProtobufCAllocator *al = wmem_new(alloc, ProtobufCAllocator);
  al->allocator_data = (void *)alloc;
  al->alloc = &wmem_pbuf_alloc;
  al->free = &wmem_pbuf_free;
  return al;
}
