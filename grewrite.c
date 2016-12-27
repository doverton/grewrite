#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "grewrite.h"

static void udp_recalc_cksum(uint8_t *udphdr, in_addr_t src, in_addr_t dst)
{
	uint32_t cksum = 0;
	uint16_t len = udp_get_len(udphdr);
	uint16_t *d16 = (uint16_t *)udphdr;

	udp_set_cksum(udphdr, 0);
	
	cksum += ntohs(src & 0xffff);
	cksum += ntohs(src >> 16);
	cksum += ntohs(dst & 0xffff);
	cksum += ntohs(dst >> 16);
	cksum += IPPROTO_UDP;
	cksum += len;

	while (len >= 2) {
		cksum += ntohs(*d16++);
		len -= 2;
	}
	if (len)
		cksum += (*(uint8_t *)d16) << 8;

	while (cksum > 0xffff)
		cksum = (cksum & 0xffff) + (cksum >> 16);

	udp_set_cksum(udphdr, ~cksum);
}

static void ip_recalc_cksum(uint8_t *iphdr)
{
	size_t words = ip_get_hl(iphdr) << 1;
	uint16_t *h16 = (uint16_t *)iphdr;
	uint32_t cksum = 0;

	ip_set_cksum(iphdr, 0);

	while (words-- > 0)
		cksum += ntohs(*h16++);
	while (cksum > 0xffff)
		cksum = (cksum & 0xffff) + (cksum >> 16);

	ip_set_cksum(iphdr, ~cksum);
}

static void dump(uint8_t *data, size_t len)
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

static void bytes_transform_out(uint8_t *buf, size_t size, const char *key)
{
	uint8_t *end = buf + size;
	const char *ptr = key;
	const char *kend = key + strlen(key);
	uint8_t last = 0x7f;

	while (buf < end) {
		*buf ^= last ^ *ptr++;
		last = *buf++;

		if (ptr == kend)
			ptr = key;
	}
}

static void bytes_transform_in(uint8_t *buf, size_t size, const char *key)
{
	uint8_t *end = buf + size;
	const char *ptr = key;
	const char *kend = key + strlen(key);
	uint8_t last = 0x7f;
	uint8_t next;

	while (buf < end) {
		next = *buf;
		*buf++ ^= last ^ *ptr++;
		last = next;

		if (ptr == kend)
			ptr = key;
	}
}

static void gre_transform_udp(uint8_t *iphdr, uint8_t *grehdr, struct config *conf)
{
	/*
         * UDP header is 4 bytes longer than GRE header so will clobber
         * ver/ihl/tos/tot_len fields. Copy the first 2 bytes over the
         * checksum field, which is now redundant (UDP header also has a
         * checksum), and the length is copied out and adjusted to fit
         * in the equivalent udp_len field).
         */
	uint8_t *inner = grehdr + 4;
	uint16_t udp_len = ip_get_tot_len(inner) + 4;

	ip_set_cksum(inner, *(uint16_t *)inner);

	udp_set_sport(grehdr, conf->sport);
	udp_set_dport(grehdr, conf->dport);
	udp_set_len(grehdr, udp_len);

	if (conf->key)
		bytes_transform_out(grehdr + 8, udp_len - 8, conf->key);

	udp_recalc_cksum(grehdr, ip_get_src(iphdr), ip_get_dst(iphdr));

	ip_set_proto(iphdr, IPPROTO_UDP);
	ip_recalc_cksum(iphdr);	
}

static void udp_transform_gre(uint8_t *iphdr, uint8_t *udphdr, struct config *conf)
{
	uint8_t *inner = udphdr + 4;
	uint16_t len = udp_get_len(udphdr);

	if (conf->key)
		bytes_transform_in(udphdr + 8, len - 8, conf->key);

	memset(udphdr, 0, 4);
	gre_set_proto(udphdr, ETHERTYPE_IP);
	
	/* 
         * Restore IP ver/ihl/tos (stored in checksum field), tot_len
         * from UDP length, and recalculate inner IP checksum.
         */
	*(uint16_t *)inner = ip_get_cksum(inner);
	ip_set_tot_len(inner, len - 4);
	ip_recalc_cksum(inner);


	ip_set_proto(iphdr, IPPROTO_GRE);
	ip_recalc_cksum(iphdr);
}

static int is_simple_ip_header(const uint8_t *iphdr)
{
	uint16_t frag_off = ntohs(*(const uint16_t *)(iphdr + 6));

	return ((frag_off >> 13) & 1) == 0 && (frag_off & 8191) == 0;
}

static void iso_isis_save_header(uint8_t *isohdr)
{
	/* Save the parts of the ISO header that
           will get overwritten by UDP checksum:
           pdu_hlen => version2
           system id length => reserved
         */
	iso_set_version2(isohdr, iso_get_pdu_hlen(isohdr));
	iso_set_reserved(isohdr, iso_get_sysid_len(isohdr));
}

static void iso_isis_restore_header(uint8_t *isohdr)
{
	iso_set_proto(isohdr, ISO_PROTO_ISIS);
	iso_set_pdu_hlen(isohdr, iso_get_version2(isohdr));
	iso_set_version(isohdr, 1);
	iso_set_sysid_len(isohdr, iso_get_reserved(isohdr));
	iso_set_version2(isohdr, 1);
	iso_set_reserved(isohdr, 0);
}


static int is_eligible_iso_isis_header(uint8_t *isohdr)
{
	return iso_get_proto(isohdr) == ISO_PROTO_ISIS &&
		iso_get_version(isohdr) == 1 &&
		iso_get_version2(isohdr) == 1 &&
		iso_get_reserved(isohdr) == 0;
}

static int is_eligible_gre_header(uint8_t *grehdr)
{
	return grehdr[0] == 0 && grehdr[1] == 0 && gre_get_proto(grehdr) == ETHERTYPE_IP;
}

static int is_eligible_udp_header(uint8_t *udphdr, struct config *conf)
{
	return (udp_get_sport(udphdr) == conf->dport && udp_get_dport(udphdr) == conf->sport);
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *conf)
{
	uint8_t *data = NULL;
	size_t len = 0;
	
	struct nfqnl_msg_packet_hdr *ph;

	if ((ph = nfq_get_msg_packet_hdr(nfa)) == NULL) {
		fprintf(stderr, "bad packet?\n");
		return 0;
	}
	if (ntohs(ph->hw_protocol) == ETHERTYPE_IP && (len = nfq_get_payload(nfa, &data)) > 0 &&
		is_simple_ip_header(data)) {

		size_t hlen = ip_get_hl(data) << 2;
		uint8_t proto = ip_get_proto(data);

		if (proto == IPPROTO_GRE) {
			if (is_eligible_gre_header(data + hlen))
				gre_transform_udp(data, data + hlen, conf);
		} else if (proto == IPPROTO_UDP) {
			if (is_eligible_udp_header(data + hlen, conf))
				udp_transform_gre(data, data + hlen, conf);
		}
	}
	
	return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, len, data);
}

int main(int argc, char *argv[]) 
{
	struct config conf = {
		.sport = 65109 - 8192 - 5102,
		.dport = 5102,
		.queue = QUEUE_NUM,
		.key = ".susageP"
	};

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	char buf[4096] __attribute__ ((aligned));
	int rcvbuf = 32768 * 1024;
	int rv;
	int fd;

	if (argc != 3) {
		fprintf(stderr, "usage: %s <sport> <dport>\n", argv[0]);
		exit(1);
	}

	conf.sport = atoi(argv[1]);
	conf.dport = atoi(argv[2]);

	if ((h = nfq_open()) == NULL) {
		fprintf(stderr, "%s: failed to open nfq\n", argv[0]);
		exit(1);
	}
	
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "%s: failed to bind for AF_NET: %s\n", argv[0], strerror(errno));
		exit(1);
	}

	if ((qh = nfq_create_queue(h, conf.queue, cb, &conf)) == NULL) {
		fprintf(stderr, "%s: failed to create queue", argv[0]);
		exit(1);
	}

	if (nfq_set_queue_maxlen(qh, 262144) < 0) {
		fprintf(stderr, "%s: failed to set queue length", argv[0]);
		exit(1);
	}

	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "%s: failed to set copy packet mode\n", argv[0]);
		exit(1);
	}

	fd = nfq_fd(h);
	
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
		fprintf(stderr, "%s: failed to set receive buffer size\n", argv[0]);
		exit(1);
	}

	while (1) {
		while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0)
			nfq_handle_packet(h, buf, rv);
		if (errno == ENOBUFS) 
			fprintf(stderr, "%s: out of buffer space, ignoring.\n", argv[0]);
		else
			break;
	}
	if (errno != 0)
		fprintf(stderr, "%s: failed to recv: %s\n", argv[0], strerror(errno));

	nfq_destroy_queue(qh);
	nfq_close(h);

	return 0;
}

