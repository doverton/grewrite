#if !defined(GREWRITE_H)
# define GREWRITE_H

#define DEFAULT_PORT 22205

#define ETHERTYPE_PPP 0x880b
#define ETHERTYPE_ISO 0x00fe

#define ISO_PROTO_ISIS 0x83
#define ISO_PROTO_ESIS 0x82

struct config {
	const char *prog;
	const char *tapdev;
	int queue;
	uint32_t queue_maxlen;
	uint16_t sport;
	uint16_t dport;
	const char *key;
	int_least8_t df;
	int_least8_t dscp;
	int_least8_t flow_labels;
	int_least8_t verbose;
	int rcvbuf;
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

static inline void ether_set_shost(uint8_t* ethhdr, const uint8_t *hwaddr)
{
	memcpy(ethhdr + ETH_ALEN, hwaddr, ETH_ALEN);
}

static inline uint16_t ether_get_ethertype(const uint8_t *ethhdr)
{
	return ntohs(*(const uint16_t *)(ethhdr + 12));
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

static inline void ip_set_df(uint8_t *iphdr, uint8_t df)
{
	iphdr[6] = (iphdr[6] & ~0x40) | (df & 1) << 6;
}

static inline void ip_set_dscp(uint8_t *iphdr, uint8_t dscp)
{
	iphdr[1] = (iphdr[1] & 3) | (dscp & 63) << 2;
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
	return ntohl(*(const uint32_t *)ip6hdr) & 0xfffff;
}

static inline void ipv6_set_flow_label(uint8_t *ip6hdr, uint32_t flow_label)
{
	*(uint32_t *)ip6hdr = htonl((ntohl(*(uint32_t *)ip6hdr) & ~0xfffff) | (flow_label & 0xfffff));
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

static inline const struct in6_addr *ipv6_get_src(const uint8_t *ip6hdr)
{
	return (const struct in6_addr *)(ip6hdr + 8);
}

static inline const struct in6_addr *ipv6_get_dst(const uint8_t *ip6hdr)
{
	return (const struct in6_addr *)(ip6hdr + 24);
}

static inline uint16_t icmp6_get_typecode(const uint8_t *icmp6hdr)
{
	return ntohs(*(uint16_t *)icmp6hdr);
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

static inline uint8_t iso_isis_get_sysid_len(const uint8_t *isohdr)
{
	return isohdr[3];
}

static inline void iso_isis_set_sysid_len(uint8_t *isohdr, uint8_t sysid_len)
{
	isohdr[3] = sysid_len;
}

static inline uint8_t iso_get_pdu_type(const uint8_t *isohdr)
{
	return isohdr[4] & 31;
}

static inline void iso_set_pdu_type(uint8_t *isohdr, uint8_t pdu_type)
{
	isohdr[4] = (isohdr[4] & (7 << 5)) | (pdu_type & 31);
}

static inline uint8_t iso_get_reserved(const uint8_t *isohdr)
{
	return isohdr[4] >> 5;
}

static inline void iso_set_reserved(uint8_t *isohdr, uint8_t reserved)
{
	isohdr[4] = (reserved & 7) << 5 | (isohdr[4] & 31);
}

static inline uint8_t iso_isis_get_version2(const uint8_t *isohdr)
{
	return isohdr[5];
}

static inline void iso_isis_set_version2(uint8_t *isohdr, uint8_t version2)
{
	isohdr[5] = version2;
}

static inline uint8_t iso_isis_get_reserved2(const uint8_t *isohdr)
{
	return isohdr[6];
}

static inline void iso_isis_set_reserved2(uint8_t *isohdr, uint8_t reserved2)
{
	isohdr[6] = reserved2;
}

static inline uint16_t iso_esis_get_cksum(const uint8_t *isohdr)
{
	return ntohs(*(uint16_t *)(isohdr + 7));
}

static inline void iso_esis_set_cksum(uint8_t *isohdr, uint16_t cksum)
{
	*(uint16_t *)(isohdr + 7) = htons(cksum);
}

int transform_ip_packet(uint8_t *iphdr, size_t size, struct config *conf);

#endif
