/* length-prefixed.c
 * Functions for working with length-prefixed data
 * Copyright 2018, Maciej Krüger <mkg20001@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <epan/packet.h>   /* Should be first Wireshark include (other than config.h) */
#include "length-prefixed.h"

// modified tvb_get_varint to tell when bytes are missing (uses ENC_PROTOBUF_VARINT version)
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

gchar* lp_decode_cut(tvbuff_t *tvb, const guint offset, int *bytesCount, int cutBytes) {
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
  return tvb_format_text(tvb, offset + prefixLength, length - cutBytes);
}
gchar* lp_decode(tvbuff_t *tvb, const guint offset, int *bytesCount) {
  return lp_decode_cut(tvb, offset, bytesCount, 0);
}

guint64 _pow(const guint64 x, int y) {
  guint64 r = x;
  y--;
  while(y--) {
    r*=x;
  }
  return r;
}

// Ported from https://github.com/nodejs/node/blob/1d2fd8b65bacaf4401450edc8ed529106cbcfc67/lib/internal/buffer.js#L360-L371
guint32 readInt32Be(const guint8* data) { // TODO: check endiannes
  return (guint32)((data[0] * _pow(2, 32)) + (data[1] * _pow(2, 16)) + (data[2] * _pow(2, 8)) + (data[3]));
}

gchar* lp_decode_fixed_cut(tvbuff_t *tvb, const guint offset, const guint prefixLength, int *bytesCount, int cutBytes) {
  *bytesCount = prefixLength;
  if (!tvb_offset_exists(tvb, offset + prefixLength - 1)) {
    return NULL;
  }
  guint8* pref = tvb_get_string_enc(wmem_file_scope(), tvb, offset, prefixLength, ENC_NA);
  guint length;
  length = readInt32Be(pref); // tvb_get_bits32(tvb, offset, prefixLength, ENC_NA);
  *bytesCount = prefixLength + length;
  if (!tvb_offset_exists(tvb, offset + *bytesCount - 1)) {
    return NULL;
  }
  return tvb_format_text(tvb, offset + prefixLength, length - cutBytes);
}
gchar* lp_decode_fixed(tvbuff_t *tvb, const guint offset, const guint prefixLength, int *bytesCount) {
  return lp_decode_fixed_cut(tvb, offset, prefixLength, bytesCount, 0);
}