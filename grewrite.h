#if !defined(GREWRITE_H)
# define GREWRITE_H

#define NF_PREROUTING 0
#define NF_POSTROUTING 4

#define DEFAULT_QUEUE_NUM 65109
#define DEFAULT_PORT 22205

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_IPV6 0x86dd
#define ETHERTYPE_PPP 0x880b
#define ETHERTYPE_ISO 0x00fe

#define ISO_PROTO_ISIS 0x83

struct config {
	const char *prog;
	uint16_t sport;
	uint16_t dport;
	const char *key;
	int df;
	int tos;
	int queue;
	int rmem;
	int noflow;
	int verbose;
	int check_rmem_max;
};

static inline uint16_t gre_get_proto(const uint8_t *grehdr)
{
	return ntohs(*(const uint16_t *)(grehdr + 2));
}

static inline void gre_set_proto(uint8_t *grehdr, uint16_t proto)
{
	*(uint16_t *)(grehdr + 2) = htons(proto);
}

static inline uint16_t udp_get_sport(const uint8_t *udphdr)
{
	return ntohs(*(const uint16_t *)udphdr);
}

static inline void udp_set_sport(uint8_t *udphdr, uint16_t sport)
{
	*(uint16_t *)udphdr = htons(sport);
}

static inline uint16_t udp_get_dport(const uint8_t *udphdr)
{
	return ntohs((*(const uint16_t *)(udphdr + 2)));
}

static inline void udp_set_dport(uint8_t *udphdr, uint16_t dport)
{
	*(uint16_t *)(udphdr + 2) = htons(dport);
}

static inline uint16_t udp_get_len(const uint8_t *udphdr)
{
	return ntohs(*(const uint16_t *)(udphdr + 4));
}

static inline void udp_set_len(uint8_t *udphdr, uint16_t len)
{
	*(uint16_t *)(udphdr + 4) = htons(len);
}

static inline void udp_set_cksum(uint8_t *udphdr, uint16_t cksum)
{
	*(uint16_t *)(udphdr + 6) = htons(cksum);
}

static inline uint8_t ip_get_version(const uint8_t *iphdr)
{
	return iphdr[0] >> 4;
}

static inline uint8_t ip_get_hl(const uint8_t *iphdr)
{
	return (*iphdr & 7);
}

static inline uint16_t ip_get_tot_len(const uint8_t *iphdr)
{
	return ntohs(*(const uint16_t *)(iphdr + 2));
}

static inline void ip_set_tot_len(uint8_t *iphdr, uint16_t tot_len)
{
	*(uint16_t *)(iphdr + 2) = htons(tot_len);
}

static inline uint16_t ip_get_frag(const uint8_t *iphdr)
{
	return ntohs(*(const uint16_t *)(iphdr + 6));
}

static inline uint8_t ip_get_proto(const uint8_t *iphdr)
{
	return iphdr[9];
}

static inline void ip_set_proto(uint8_t *iphdr, uint8_t proto)
{
	iphdr[9] = proto;
}

static inline in_addr_t ip_get_src(const uint8_t *iphdr)
{
	return *(in_addr_t *)(iphdr + 12);
}

static inline in_addr_t ip_get_dst(const uint8_t *iphdr)
{
	return *(in_addr_t *)(iphdr + 16);
}

static inline uint16_t ip_get_cksum(const uint8_t *iphdr)
{
	return ntohs(*(uint16_t *)(iphdr + 10));
}

static inline void ip_set_cksum(uint8_t *iphdr, uint16_t cksum)
{
	*(uint16_t *)(iphdr + 10) = htons(cksum);
}

static inline uint32_t ipv6_get_flow_label(const uint8_t *ip6hdr)
{
	return ntohl(*(const uint32_t *)ip6hdr) & 1048575;
}

static inline void ipv6_set_flow_label(uint8_t *ip6hdr, uint32_t flow_label)
{
	*(uint32_t *)ip6hdr = htonl((ntohl(*(uint32_t *)ip6hdr) & ~1048575) | (flow_label & 1048575));
}

static inline uint16_t ipv6_get_payload_len(const uint8_t *ip6hdr)
{
	return ntohs(*(const uint16_t *)(ip6hdr + 4));
}

static inline void ipv6_set_payload_len(uint8_t *ip6hdr, uint16_t payload_len)
{
	*(uint16_t *)(ip6hdr + 4) = htons(payload_len);
}

static inline uint8_t ipv6_get_next_header(const uint8_t *ip6hdr)
{
	return ip6hdr[6];
}

static inline uint8_t iso_get_proto(const uint8_t *isohdr)
{
	return isohdr[0];
}

static inline void iso_set_proto(uint8_t *isohdr, uint8_t proto)
{
	isohdr[0] = proto;
}

static inline uint8_t iso_get_pdu_hlen(const uint8_t *isohdr)
{
	return isohdr[1];
}

static inline void iso_set_pdu_hlen(uint8_t *isohdr, uint8_t pdu_hlen)
{
	isohdr[1] = pdu_hlen;
}

static inline uint8_t iso_get_version(const uint8_t *isohdr)
{
	return isohdr[2];
}

static inline void iso_set_version(uint8_t *isohdr, uint8_t version)
{
	isohdr[2] = version;
}

static inline uint8_t iso_get_sysid_len(const uint8_t *isohdr)
{
	return isohdr[3];
}

static inline void iso_set_sysid_len(uint8_t *isohdr, uint8_t sysid_len)
{
	isohdr[3] = sysid_len;
}

static inline uint8_t iso_get_pdu_type(const uint8_t *isohdr)
{
	return isohdr[4];
}

static inline uint8_t iso_get_version2(const uint8_t *isohdr)
{
	return isohdr[5];
}

static inline void iso_set_version2(uint8_t *isohdr, uint8_t version2)
{
	isohdr[5] = version2;
}

static inline uint8_t iso_get_reserved(const uint8_t *isohdr)
{
	return isohdr[6];
}

static inline void iso_set_reserved(uint8_t *isohdr, uint8_t reserved)
{
	isohdr[6] = reserved;
}

static inline void hexdump(uint8_t *data, size_t len)
{
        for (size_t i = 0; i < len; i++) {
                if (i % 8 == 0)
                        printf(" ");
                else if (i % 16 == 0)
                        printf("\n");
                printf("%02x ", data[i]);
        }
        printf("\n");

}

#endif
