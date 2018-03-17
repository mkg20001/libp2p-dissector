/* addr-pair.c
 * Functions for working with addr:port pair structs
 * Copyright 2018, Maciej Krüger <mkg20001@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <epan/packet.h>   /* Should be first Wireshark include (other than config.h) */
#include <epan/to_str.h>
#include <stdio.h>
#include "addr-pair.h"

addr_pair* addrpair_create(wmem_allocator_t *alloc, const packet_info *pinfo) {
  addr_pair* target = wmem_new(alloc, addr_pair);
  target->defined = TRUE;
  copy_address_wmem(alloc, &target->addr, &pinfo->src);
  target->port = pinfo->srcport;
  return target;
}

gboolean addrpair_cmp(const packet_info* pinfo, const addr_pair* cmp) {
  if (!cmp) return FALSE;
  return pinfo->srcport == cmp->port && addresses_equal(&pinfo->src, &cmp->addr);
}

gchar* addrpair_to_display(const addr_pair* src) {
  if (!src) return NULL;
  char* addr = address_to_display(wmem_packet_scope(), &src->addr);
  char port[sizeof(src->port)];
  sprintf(port, "%d", src->port);
  char* out;
  out = (char *)wmem_alloc(wmem_packet_scope(), strlen(addr) + strlen(port) + 1);
  strcpy(out, addr);
  strcat(out, ":");
  strcat(out, port);
  return out;
}
