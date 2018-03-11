/* length-prefixed.c
 * Functions for working with length-prefixed data
 * Copyright 2018, Maciej Krüger <mkg20001@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <epan/packet.h>   /* Should be first Wireshark include (other than config.h) */
#include <stdio.h>
#include "length-prefixed.h"

// modified tvb_get_varint to tell when bytes are missing
guint
get_varint(tvbuff_t *tvb, guint offset, guint maxlen, guint64 *value, gboolean *missing)
{
  *value = 0;

  guint i;
  guint64 b; /* current byte */

  for (i = 0; ((i < FT_VARINT_MAX_LEN) && (i < maxlen)); ++i) {
    if (!tvb_offset_exists(tvb, offset)) {
      *missing = TRUE;
      return i;
    }
    b = tvb_get_guint8(tvb, offset++);
    *value |= ((b & 0x7F) << (i * 7)); /* add lower 7 bits to val */

    if (b < 0x80) {
      /* end successfully becauseof last byte's msb(most significant bit) is zero */
      return i + 1;
    }
  }

  return 0; /* 10 bytes scanned, but no bytes' msb is zero */
}

gchar* lp_decode(tvbuff_t *tvb, const guint offset, int *bytesCount) {
  *bytesCount = 1;
  if (!tvb_offset_exists(tvb, offset)) {
    return NULL;
  }
  guint64 length64;
  gboolean tempMissing = 0;
  guint prefixLength = get_varint(tvb, offset, 20, &length64, &tempMissing);
  guint32 length = (guint32)length64;
  if (tempMissing) {
    *bytesCount = prefixLength + 1;
    return NULL;
  }
  *bytesCount = prefixLength + length;
  if (!tvb_offset_exists(tvb, offset + *bytesCount - 1)) {
    return NULL;
  }
  fprintf(stderr, "@= len=%i, total=%i\n", offset + length + prefixLength, tvb_captured_length(tvb));
  fprintf(stderr, "@of=%i, prf=%i, len=%i, bytes=%i\n", offset, prefixLength, length, *bytesCount);
  return tvb_format_text(tvb, offset + prefixLength, length);
}