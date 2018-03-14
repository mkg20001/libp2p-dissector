/* addr-pair.c
 * Functions for working with addr:port pair structs
 * Copyright 2018, Maciej Krüger <mkg20001@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <epan/packet.h>   /* Should be first Wireshark include (other than config.h) */
#include "addr-pair.h"

addr_pair* addrpair_store(const packet_info* pinfo) {
  addr_pair* target = wmem_new(wmem_file_scope(), addr_pair);
  target->defined = TRUE;
  copy_address_wmem(wmem_file_scope(), &target->addr, &pinfo->src);
  target->port = pinfo->srcport;
  return target;
}

gboolean addrpair_cmp(const packet_info* pinfo, const addr_pair* cmp) {
  if (!cmp) return FALSE;
  return pinfo->srcport == cmp->port && addresses_equal(&pinfo->src, &cmp->addr);
}