typedef struct _addr_pair {
    gboolean defined;
    address addr;
    guint32 port;
} addr_pair;

addr_pair* addrpair_create(wmem_allocator_t *alloc, const packet_info *pinfo);
gboolean addrpair_cmp(const packet_info* pinfo, const addr_pair* cmp);
gchar* addrpair_to_display(const addr_pair* src);
