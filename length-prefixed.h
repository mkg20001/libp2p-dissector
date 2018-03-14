#define MAX_LENGTH ((1024 * 1024) * 4)

gchar* lp_decode_cut(tvbuff_t *tvb, guint offset, int *bytesCount, int cutBytes);
gchar* lp_decode(tvbuff_t *tvb, guint offset, int *bytesCount);
gchar* lp_decode_fixed_cut(tvbuff_t *tvb, guint offset, guint prefixLength, int *bytesCount, int cutBytes);
gchar* lp_decode_fixed(tvbuff_t *tvb, guint offset, guint prefixLength, int *bytesCount);