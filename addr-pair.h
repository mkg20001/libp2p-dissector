typedef struct _addr_pair {
    gboolean defined;
    address addr;
    guint32 port;
} addr_pair;

addr_pair* addrpair_store(const packet_info* pinfo);
gboolean addrpair_cmp(const packet_info* pinfo, const addr_pair* cmp);