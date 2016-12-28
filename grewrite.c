#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <getopt.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "grewrite.h"

static int is_simple_ip_header(const uint8_t *iphdr)
{
	uint16_t frag = ip_get_frag(iphdr);

	return ((frag >> 13) & 1) == 0 && (frag & 8191) == 0;
}

static int is_eligible_gre_header(uint8_t *grehdr)
{
	return grehdr[0] == 0 && grehdr[1] == 0;
}

static int is_eligible_udp_header(uint8_t *udphdr, struct config *conf)
{
	return udp_get_sport(udphdr) == conf->dport &&
		udp_get_dport(udphdr) == conf->sport;
}

static int is_eligible_iso_isis_header(uint8_t *isohdr)
{
	return iso_get_proto(isohdr) == ISO_PROTO_ISIS &&
		iso_get_version(isohdr) == 1 &&
		iso_get_sysid_len(isohdr) == 0 &&
		iso_get_version2(isohdr) == 1 &&
		iso_get_reserved(isohdr) == 0;
}

static int is_eligible_ipv6_header(uint8_t *ip6hdr)
{
	return ipv6_get_flow_label(ip6hdr) == 0 &&
		ipv6_get_payload_len(ip6hdr) != 0; /* e.g, for jumbograms */
}

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

	cksum = ~cksum;
	udp_set_cksum(udphdr, cksum == 0 ? 0xffff : cksum);
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

static int gre_transform_udp(uint8_t *iphdr, uint8_t *grehdr, struct config *conf)
{
	uint16_t type = gre_get_proto(grehdr);
	uint16_t udp_len = 0;
	uint8_t *inner = grehdr + 4;

	if (type == ETHERTYPE_IPV4) {
		/*
		 * Inner is an IP header - UDP clobbers ver/ihl/tos/tot_len.
                 * Strategy here is to copy ver/ihl/tos to the IP checksum
                 * field (we calculate a UDP checksum to replace this), and
                 * adjust tot_len then store in udp_len.
                 */
		udp_len = ip_get_tot_len(inner) + 4;
		ip_set_cksum(inner, *(uint16_t *)inner);
	} else if (type == ETHERTYPE_IPV6) {
		/*
		 * Inner is an IPv6 header - UDP clobbers version/tc/flow label.
		 * We make sure flow labels aren't in use which give us 20 bits
		 * and means we only need to save version and tc. We move the
		 * payload length into the UDP header, 3rd and 4th octets of the
		 * source address into the space left over from that, and then
		 * the version and traffic class can move to where the address
		 * octets lived - which puts them where the IPv4 checksum field,
		 * giving the decoder a single place to hunt out the IP version.
		 */
		if (is_eligible_ipv6_header(inner)) {
			udp_len = ipv6_get_payload_len(inner) + 44;
			ipv6_set_payload_len(inner, ip_get_cksum(inner));
			ip_set_cksum(inner, *(uint16_t *)inner);
		}
	} else if (type == ETHERTYPE_ISO) {
		/*
                 * Inner is an 8-byte ISO header - UDP clobbers protocol/
		 * pdu_hlen/version/sysid_len. We first make sure this actually
		 * is an IS-IS packet. If that's the case, the strategy is to
		 * copy pdu_hlen to version2. sysid_len is required to be
		 * zero for cisco, so we discard that and set reserved2 to
		 * 255 (all 1s). This allows the decoder to distinguish this
		 * from an IP packet where all 1s would indicate R/DF/MF flags
		 * all set in IPv4 (an invalid combination), or IP proto 255
		 * for IPv6, which is reserved.
		 */
		if (is_eligible_iso_isis_header(inner)) {
			udp_len = ip_get_tot_len(iphdr) - (grehdr - iphdr);
			iso_set_version2(inner, iso_get_pdu_hlen(inner));
			iso_set_reserved(inner, 255);
		}
	}

	if (udp_len) {
		udp_set_sport(grehdr, conf->sport);
		udp_set_dport(grehdr, conf->dport);
		udp_set_len(grehdr, udp_len);

		if (conf->key)
			bytes_transform_out(grehdr + 8, udp_len - 8, conf->key);

		udp_recalc_cksum(grehdr, ip_get_src(iphdr), ip_get_dst(iphdr));

		ip_set_proto(iphdr, IPPROTO_UDP);
		ip_recalc_cksum(iphdr);
		return 0;
	} else {
		/* Packet could not be transformed */
		return 1;
	}
}

static int udp_transform_gre(uint8_t *iphdr, uint8_t *udphdr, struct config *conf)
{
	uint8_t *inner = udphdr + 4;
	uint16_t udp_len = udp_get_len(udphdr);
	uint16_t type = 0;

	if (udp_len >= 16) {
		/* Erase length and checksum to restore GRE header */
		memset(udphdr, 0, 4);

		if (conf->key)
			bytes_transform_in(udphdr + 8, udp_len - 8, conf->key);

		if (iso_get_pdu_type(inner) >> 5 == 0 && iso_get_reserved(inner) == 255) {
			/* It's IS-IS, based on our transform rules (see above) */
			type = ETHERTYPE_ISO;

			iso_set_proto(inner, ISO_PROTO_ISIS);
			iso_set_pdu_hlen(inner, iso_get_version2(inner));
			iso_set_version(inner, 1);
			iso_set_sysid_len(inner, 0);
			iso_set_version2(inner, 1);
			iso_set_reserved(inner, 0);
		} else {
			/* It's IP */
			*(uint16_t *)inner = ip_get_cksum(inner);
			uint8_t version = ip_get_version(inner);

			if (version == 4) {
				type = ETHERTYPE_IPV4;

				ip_set_tot_len(inner, udp_len - 4);
				ip_recalc_cksum(inner);
			} else if (version == 6) {
				type = ETHERTYPE_IPV6;

				ip_set_cksum(inner, ipv6_get_payload_len(inner));
				ipv6_set_payload_len(inner, udp_len - 44);
			}
		}
	}

	if (type != 0) {
		gre_set_proto(udphdr, type);

		ip_set_proto(iphdr, IPPROTO_GRE);
		ip_recalc_cksum(iphdr);
		return 0;
	} else {
		/* Packet could not be transformed */
		return 1;
	}
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *ptr)
{
	struct config *conf = ptr;
	uint8_t *data = NULL;
	size_t len = 0;

	struct nfqnl_msg_packet_hdr *ph;
	uint16_t type;

	if ((ph = nfq_get_msg_packet_hdr(nfa)) == NULL) {
		fprintf(stderr, "bad packet?\n");
		return -1;
	}

	type = ntohs(ph->hw_protocol);

	if (type == ETHERTYPE_IPV4 && (len = nfq_get_payload(nfa, &data)) > 0 &&
		is_simple_ip_header(data)) {

		size_t hlen = ip_get_hl(data) << 2;
		uint8_t proto = ip_get_proto(data);

		if (proto == IPPROTO_GRE && is_eligible_gre_header(data + hlen)) {
			if (gre_transform_udp(data, data + hlen, conf) != 0) {
				data = NULL;
				len = 0;
			}
		} else if (proto == IPPROTO_UDP && is_eligible_udp_header(data + hlen, conf)) {
			if (udp_transform_gre(data, data + hlen, conf) != 0) {
				data = NULL;
				len  = 0;
			}
		} else {
			if (conf->verbose)
				fprintf(stderr, "%s: ignoring packet with IP proto 0x%02x\n", conf->prog, proto);
		}
	} else {
		if (conf->verbose)
			fprintf(stderr, "%s: ignoring packet with type 0x%04x", conf->prog, type);
	}

	return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, len, data);
}

void usage(const char *prog) {
	printf("Usage: %s [--queue=<n>] [--sport=<port>] [--dport=<port>] [options]...\n\n", prog);
	printf("Rewrite simple GRE packets as UDP and vice versa via NFQUEUE.\n\n");
	printf("  -d, --dport=PORT	Intercept UDP packets on 'PORT'.\n");
	printf("  -f, --df-bit=BIT	Set or clear IP do-not-fragment bit.\n");
	printf("  -k, --key=KEY		Obfuscate UDP packet contents with KEY.\n");
	printf("  -m, --rmem=RMEM	Set SO_RCVBUF size on NFQUEUE socket.\n");
	printf("  -q, --queue=NFQUEUE	Which NFQUEUE to create.\n");
	printf("  -s, --sport=PORT	Emit UDP packets from 'PORT'.\n");
	printf("  -t, --tos=TOS		Set IP type of service field to TOS.\n\n");
	printf("Note: Due to the size difference between the simplest GRE and UDP\n");
	printf("      headers, %s can only rewrite packets for which special\n", prog);
	printf("      handlers have been written; at this time IPv4, IPv6, and\n");
	printf("      IS-IS may be transported.\n\n");
}

int parse_args(int argc, char *argv[], struct config *conf)
{
	int c;

	static const struct option options[] = {
		{ "sport",   required_argument, NULL, 's' },
		{ "dport",   required_argument, NULL, 'd' },
		{ "df-bit",  required_argument, NULL, 'f' },
		{ "tos",     required_argument, NULL, 't' },
		{ "key",     required_argument, NULL, 'k' },
		{ "queue",   required_argument, NULL, 'q' },
		{ "rmem",    required_argument, NULL, 'm' },
		{ "help",    no_argument,       NULL, 'h' },
		{ "verbose", no_argument,       NULL, 'v' },
		{ NULL,     0,                  NULL, 0   }
	};

	conf->prog = argv[0];

	while (1) {
		int index = 0;
		int n;
		char *err;

		if ((c = getopt_long(argc, argv, "s:d:f:t:k:q:m:hv",
			options, &index)) < 0)
			break;

		switch (c) {
		case 's':
			n = strtol(optarg, &err, 0);
			if (*err != 0) {
				fprintf(stderr, "%s: %s: source port is invalid.\n", argv[0], optarg);
				exit(2);
			} else if (n < 1 || n > 65535) {
				fprintf(stderr, "%s: %d: source port is out of range.\n", argv[0], n);
				exit(2);
			}
			conf->sport = n;
			break;
		case 'd':
			n = strtol(optarg, &err, 0);
			if (*err != 0) {
				fprintf(stderr, "%s: %s: destination port is invalid.\n", argv[0], optarg);
				exit(2);
			} else if (n < 1 || n > 65535) {
				fprintf(stderr, "%s: %d: destination port is out of range.\n", argv[0], n);
				exit(2);
			}
			conf->dport = n;
			break;
		case 'f':
			if (strcmp(optarg, "1") == 0 || strcasecmp(optarg, "yes") == 0 ||
					strcasecmp(optarg, "true") == 0) {
				conf->df = 1;
			} else if (strcmp(optarg, "0") == 0 || strcasecmp(optarg, "no") == 0 ||
					strcasecmp(optarg, "false") == 0) {
				conf->df = 0;
			} else {
				fprintf(stderr, "%s: %s: invalid option for don't fragment bit.\n", argv[0], optarg);
				exit(2);
			}
			break;
		case 't':
			n = strtol(optarg, &err, 0);
			if (*err != 0) {
				fprintf(stderr, "%s: %s: invalid value for type of service.\n", argv[0], optarg);
				exit(2);
			} else if (n < 0 || n > 255) {
				fprintf(stderr, "%s: %d: type of service is out of range.\n", argv[0], n);
				exit(2);
			}
			break;
		case 'k':
			conf->key = optarg;
			break;
		case 'q':
			n = strtol(optarg, &err, 0);
			if (*err != 0) {
				fprintf(stderr, "%s: %s: invalid value for nfqueue number.\n", argv[0], optarg);
				exit(2);
			} else if (n < 0 || n > 65535) {
				fprintf(stderr, "%s: %d: nfqueue number is out of range.\n", argv[0], n);
				exit(2);
			}
			conf->queue = n;
			break;
		case 'm':
			n = strtol(optarg, &err, 0);
			if (*err != 0) {
				fprintf(stderr, "%s: %s: invalid value for recvbuf size.\n", argv[0], optarg);
				exit(2);
			} else if (n < 1) {
				fprintf(stderr, "%s: %d: recvbuf size is out of range.\n", argv[0], n);
				exit(2);
			}
			conf->rmem = n;
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
			break;
		case 'v':
			conf->verbose = 1;
			break;
		default:
			exit(2);
			break;
		}
	}

	return 0;
}

int main(int argc, char *argv[])
{
	struct config conf = {
		.queue = DEFAULT_QUEUE_NUM,
		.sport = DEFAULT_PORT,
		.dport = DEFAULT_PORT,
		.key = NULL,
		.df = -1,	/* Don't mess with DF bit */
		.tos = -1,	/* Don't mess with TOS */
		.rmem = -1,	/* Don't mess with SO_RECVBUF */
		.verbose = 0
	};

	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	char buf[4096] __attribute__ ((aligned));
	int rv;
	int fd;

	parse_args(argc, argv, &conf);

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

	if (conf.rmem > -1 && setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &conf.rmem, sizeof(conf.rmem)) < 0) {
		fprintf(stderr, "%s: failed to set receive buffer size\n", argv[0]);
		exit(1);
	}

	while (1) {
		while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0)
			nfq_handle_packet(h, buf, rv);
		if (errno != ENOBUFS) {
			if (conf.verbose)
				fprintf(stderr, "%s: out of buffer space, ignoring.\n", argv[0]);
		} else {
			break;
		}
	}
	if (errno != 0)
		fprintf(stderr, "%s: failed to recv: %s\n", argv[0], strerror(errno));

	nfq_destroy_queue(qh);
	nfq_close(h);

	return 0;
}

