#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include "grewrite.h"
#include "nfqueue.h"
#include "tuntap.h"

static int is_simple_ip_header(const uint8_t *iphdr)
{
	uint16_t frag = ip_get_frag(iphdr);

	return ((frag >> 13) & 1) == 0 && (frag & 8191) == 0;
}

static int is_eligible_gre_header(uint8_t *grehdr, size_t size)
{
	return size >= 4 && grehdr[0] == 0 && grehdr[1] == 0;
}

static int is_eligible_udp_header(uint8_t *udphdr, size_t size, struct config *conf)
{
	return size >= 8 && udp_get_sport(udphdr) == conf->dport &&
		udp_get_dport(udphdr) == conf->sport;
}

static int is_eligible_iso_isis_header(uint8_t *isohdr)
{
	return iso_get_proto(isohdr) == ISO_PROTO_ISIS &&
		iso_get_version(isohdr) == 1 &&
		iso_isis_get_sysid_len(isohdr) == 0 &&
		iso_isis_get_version2(isohdr) == 1 &&
		iso_isis_get_reserved2(isohdr) == 0;
}

static int is_eligible_iso_esis_header(uint8_t *isohdr)
{
	return iso_get_proto(isohdr) == ISO_PROTO_ESIS &&
		iso_get_version(isohdr) == 1 &&
		iso_get_reserved(isohdr) == 0;
}

static int is_eligible_ipv6_header(uint8_t *ip6hdr, struct config *conf)
{
	return (ipv6_get_flow_label(ip6hdr) == 0 || conf->flow_labels) &&
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

static void iso_esis_recalc_cksum(uint8_t *isohdr)
{
        uint64_t c0 = 0;
        uint64_t c1 = 0;
        uint8_t *ptr = isohdr;
        uint8_t len = iso_get_pdu_hlen(isohdr);
        int x;
        int y;

        iso_esis_set_cksum(isohdr, 0);

        while (len-- > 0) {
                c0 += *ptr++;
                c1 += c0;
        }

        c0 %= 255;
        c1 %= 255;

        x = (((ptr - isohdr) - 8) * c0 - c1) % 255;
        if (x <= 0)
                x += 255;

        y = (510 - c0 - x);
        if (y > 255)
                y -= 255;

        iso_esis_set_cksum(isohdr, x << 8 | (y & 255));
}

static void ipv6_gen_flow_label(uint8_t *ip6hdr)
{
	const struct in6_addr *src = ipv6_get_src(ip6hdr);
	const struct in6_addr *dst = ipv6_get_dst(ip6hdr);
	uint8_t proto = ipv6_get_next_header(ip6hdr);
	uint16_t sport = 0;
	uint16_t dport = 0;

	uint32_t label = 5381;

	if (proto == IPPROTO_UDP || proto == IPPROTO_UDPLITE ||
			proto == IPPROTO_TCP || proto == IPPROTO_SCTP) {
		sport = udp_get_sport(ip6hdr + 40);
		dport = udp_get_dport(ip6hdr + 40);
	} else if (proto == IPPROTO_ICMPV6) {
		sport = ntohs(*(uint16_t *)(ip6hdr + 40));
		dport = ntohs(*(uint16_t *)(ip6hdr + 44));
	}

	for (int i = 0; i < 16; i++) {
		label = ((label << 5) + label) + src->s6_addr[i];
		label = ((label << 5) + label) + dst->s6_addr[i];
	}

	label = ((label << 5) + label) + (sport & 0xff);
	label = ((label << 5) + label) + (dport & 0xff);
	label = ((label << 5) + label) + ((sport >> 8) & 0xff);
	label = ((label << 5) + label) + ((dport >> 8) & 0xff);
	label = ((label << 5) + label) + proto;

	label &= 0xfffff;

	ipv6_set_flow_label(ip6hdr, label == 0 ? 1 : label);
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

static int gre_transform_udp(uint8_t *iphdr, uint8_t *grehdr, size_t size, struct config *conf)
{
	uint16_t type = gre_get_proto(grehdr);
	uint16_t udp_len = 0;
	uint8_t *inner = grehdr + 4;

	if (type == ETHERTYPE_IP) {
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
		 * octets lived - which puts them over the IPv4 checksum field,
		 * giving the decoder a single place to hunt out the IP version.
		 */
		if (is_eligible_ipv6_header(inner, conf)) {
			udp_len = ipv6_get_payload_len(inner) + 44;
			ipv6_set_payload_len(inner, ip_get_cksum(inner));
			ip_set_cksum(inner, *(uint16_t *)inner);
		}
	} else if (type == ETHERTYPE_ISO) {
		/*
		 * Inner is an 8-byte ISO header, check for IS-IS or ES-IS.
		 */
		if (is_eligible_iso_isis_header(inner)) {
			/*
			 * IS-IS: UDP clobbers protocol/pdu_hlen/version/sysid_len.
			 * Copy pdu_hlen to version2. sysid_len is required to be
			 * zero for cisco, so we discard that and set reserved2 to
			 * 255 (all 1s). This allows the decoder to distinguish this
			 * from an IP packet where all 1s would indicate R/DF/MF flags
			 * all set in IPv4 (an invalid combination), or IP proto 255
			 * for IPv6, which is reserved.
			 */
			udp_len = ip_get_tot_len(iphdr) - (grehdr - iphdr);
			iso_isis_set_version2(inner, iso_get_pdu_hlen(inner));
			iso_isis_set_reserved2(inner, 255);
		} else if (is_eligible_iso_esis_header(inner)) {
			/*
			 * ES-IS: UDP clobbers protocol/pdu_hlen/version/reserved.
			 * Overwrite checksum field with pdu_hlen and 2nd hold time
			 * byte. This byte overlaps IPv4 flags which is then used as
			 * per IS-IS. Turn on all reserved bits so decoder knows
			 * this should be ES-IS.
			 */
			udp_len = ip_get_tot_len(iphdr) - (grehdr - iphdr);
			iso_set_reserved(inner, 7);
			iso_esis_set_cksum(inner, iso_isis_get_reserved2(inner) << 8 | iso_get_pdu_hlen(inner));
			iso_isis_set_reserved2(inner, 255);
		}
	}

	if (udp_len) {
		udp_set_sport(grehdr, conf->sport);
		udp_set_dport(grehdr, conf->dport);
		udp_set_len(grehdr, udp_len);

		if (conf->key)
			bytes_transform_out(grehdr + 8, udp_len - 8, conf->key);

		udp_recalc_cksum(grehdr, ip_get_src(iphdr), ip_get_dst(iphdr));

		if (conf->df > -1)
			ip_set_df(iphdr, conf->df ? 1 : 0);
		if (conf->dscp > -1)
			ip_set_dscp(iphdr, conf->dscp);

		ip_set_proto(iphdr, IPPROTO_UDP);
		ip_recalc_cksum(iphdr);
		return 0;
	} else {
		/* Packet could not be transformed */
		return 1;
	}
}

static int udp_transform_gre(uint8_t *iphdr, uint8_t *udphdr, size_t size, struct config *conf)
{
	uint8_t *inner = udphdr + 4;
	uint16_t udp_len = udp_get_len(udphdr);
	uint16_t type = 0;

	if (udp_len >= 16) {
		/* Erase length and checksum to restore GRE header */
		memset(udphdr, 0, 4);

		if (conf->key)
			bytes_transform_in(udphdr + 8, udp_len - 8, conf->key);

		if (iso_isis_get_reserved2(inner) == 255) {
			/* It's ISO */
			uint8_t reserved = iso_get_reserved(inner);
			if (reserved == 0) {
				/* It's IS-IS; reserved bits are not modified. */
				type = ETHERTYPE_ISO;

				iso_set_proto(inner, ISO_PROTO_ISIS);
				iso_set_pdu_hlen(inner, iso_isis_get_version2(inner));
				iso_set_version(inner, 1);
				iso_isis_set_sysid_len(inner, 0);
				iso_isis_set_version2(inner, 1);
				iso_isis_set_reserved2(inner, 0);
			} else if (reserved == 7) {
				/* It's ES-IS; reserved bits are all on. */
				uint16_t time_hlen = iso_esis_get_cksum(inner);

				type = ETHERTYPE_ISO;

				iso_set_proto(inner, ISO_PROTO_ESIS);
				iso_set_pdu_hlen(inner, time_hlen & 255);
				iso_set_version(inner, 1);
				iso_set_reserved(inner, 0);
				iso_isis_set_reserved2(inner, time_hlen >> 8); /* restore holdtime */
				iso_esis_recalc_cksum(inner);
			}
		} else {
			/* It's IP */
			*(uint16_t *)inner = ip_get_cksum(inner);
			uint8_t version = ip_get_version(inner);

			if (version == 4) {
				type = ETHERTYPE_IP;

				ip_set_tot_len(inner, udp_len - 4);
				ip_recalc_cksum(inner);
			} else if (version == 6) {
				type = ETHERTYPE_IPV6;

				ip_set_cksum(inner, ipv6_get_payload_len(inner));
				ipv6_set_payload_len(inner, udp_len - 44);

				if (conf->flow_labels == 1)
					ipv6_set_flow_label(inner, 0);
				else if (conf->flow_labels == 2)
					ipv6_gen_flow_label(inner);
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

int transform_ip_packet(uint8_t *iphdr, size_t size, struct config *conf)
{
	size_t hlen = ip_get_hl(iphdr) << 2;
	uint8_t proto = ip_get_proto(iphdr);

	if (!is_simple_ip_header(iphdr)) {
		if (conf->verbose)
			fprintf(stderr, "%s: ignoring IP packet due to possible fragmentation.\n", conf->prog);
		return -1;
	}

	size -= hlen;

	if (proto == IPPROTO_GRE && is_eligible_gre_header(iphdr + hlen, size)) {
	        return gre_transform_udp(iphdr, iphdr + hlen, size, conf);
	} else if (proto == IPPROTO_UDP && is_eligible_udp_header(iphdr + hlen, size, conf)) {
	        return udp_transform_gre(iphdr, iphdr + hlen, size, conf);
	} else {
	        if (conf->verbose)
			fprintf(stderr, "%s: ignoring packet with IP proto 0x%02x\n", conf->prog, proto);

		return -1;
	}
}

void usage(const char *prog) {
	printf("Usage: %s --queue=<num>|--tapdev=<name> [options]...\n\n", prog);
	printf("Rewrite simple GRE packets as UDP and vice versa.\n\n");
	printf("  -c, --dscp=DSCP       Set differentiated services code point.\n");
	printf("  -d, --dport=PORT      Intercept UDP packets on 'PORT'.\n");
	printf("  -f, --df-bit=BIT      Set or clear IP do-not-fragment bit.\n");
	printf("  -g, --ipv6-genflow    Generate new IPv6 flow labels (implies -z).\n");
	printf("  -k, --key=KEY         Obfuscate UDP packet contents with KEY.\n");
	printf("  -m, --queue-maxlen=N  Set netfilter maximum queue length (default %u).\n", DEFAULT_QUEUE_MAXLEN);
	printf("  -q, --queue=NUM       Operate on netfilter queue NUM.\n");
	printf("  -r, --rcvbuf=SIZE     Set SO_RCVBUF size on NFQUEUE socket.\n");
	printf("  -s, --sport=PORT      Emit UDP packets from 'PORT'.\n");
	printf("  -t, --tapdev=NAME     Operate on TAP device NAME.\n\n");
	printf("  -z, --ipv6-noflow     Zap IPv6 flow label even when set.\n");
	printf("Note: Due to the size difference between the simplest GRE and UDP\n");
	printf("      headers, %s can only rewrite packets for which special\n", prog);
	printf("      handlers have been written; at this time IPv4, IPv6, and\n");
	printf("      IS-IS may be transported. If a packet cannot be rewritten\n");
	printf("      it will be forwarded unmodified.\n\n");
	printf("IPv6: RFC compliant IPv6 transport is only possible when flow\n");
	printf("      labels are turned off; you can do this with:\n\n");
	printf("        sysctl net.ipv6.auto_flowlabels=0\n\n");
	printf("      Alternatively, pass the '--ipv6-noflow' option to zero\n");
	printf("      flow labels, or '--ipv6-genflow' to generate new ones.\n");
	printf("      Note that both of these options violate RFC 6437.\n");
}

int parse_args(int argc, char *argv[], struct config *conf)
{
	int c;

	static const struct option options[] = {
		{ "sport",        required_argument, NULL, 's' },
		{ "dport",        required_argument, NULL, 'd' },
		{ "df-bit",       required_argument, NULL, 'f' },
		{ "dscp",         required_argument, NULL, 'c' },
		{ "key",          required_argument, NULL, 'k' },
		{ "queue",        optional_argument, NULL, 'q' },
		{ "queue-maxlen", required_argument, NULL, 'm' },
		{ "tapdev",       optional_argument, NULL, 't' },
		{ "rcvbuf",       required_argument, NULL, 'r' },
		{ "ipv6-noflow",  no_argument,       NULL, 'z' },
		{ "ipv6-genflow", no_argument,       NULL, 'g' },
		{ "help",         no_argument,       NULL, 'h' },
		{ "verbose",      no_argument,       NULL, 'v' },
		{  NULL,          0,                 NULL,  0  }
	};

	conf->prog = argv[0];

	while (1) {
		int index = 0;
		int n;
		char *err;

		if ((c = getopt_long(argc, argv, "c:s:d:f:k:qtr:m:zghv",
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
		case 'c':
			n = strtol(optarg, &err, 0);
			if (*err != 0) {
				fprintf(stderr, "%s: %s: invalid value for DSCP.\n", argv[0], optarg);
				exit(2);
			} else if (n < 0 || n > 63) {
				fprintf(stderr, "%s: %d: DSCP is out of range.\n", argv[0], n);
				exit(2);
			}
			conf->dscp = n;
			break;
		case 'k':
			conf->key = optarg;
			break;
		case 'q':
			if (conf->tapdev) {
				fprintf(stderr, "%s: queue cannot be used with tapdev.\n", argv[0]);
				exit(2);
			}
			conf->queue = DEFAULT_QUEUE_NUM;
			if (!optarg && optind < argc && argv[optind] && argv[optind][0] && argv[optind][0] != '-') {
				n = strtol(optarg, &err, 0);
				if (*err != 0) {
					fprintf(stderr, "%s: %s: invalid value for queue number.\n", argv[0], optarg);
					exit(2);
				} else if (n < 0 || n > 65535) {
					fprintf(stderr, "%s: %d: queue number is out of range.\n", argv[0], n);
					exit(2);
				}
				conf->queue = n;
				optind++;
			}
			break;
		case 't':
			if (conf->queue > -1) {
				fprintf(stderr, "%s: tapdev cannot be used with queue.\n", argv[0]);
				exit(2);
			}
			conf->tapdev = DEFAULT_TAPDEV;
			if (!optarg && optind < argc && argv[optind] && argv[optind][0] && argv[optind][0] != '-') {
				conf->tapdev = argv[optind];
				optind++;
			}
			break;
		case 'm':
			n = strtol(optarg, &err, 0);
			if (*err != 0) {
				fprintf(stderr, "%s: %s: invalid value for maxiumum queue length.\n", argv[0], optarg);
				exit(2);
			} else if (n < 1) {
				fprintf(stderr, "%s: %d: maximum queue length is out of range.\n", argv[0], n);
				exit(2);
			}
			conf->queue_maxlen = n;
			break;
		case 'r':
			n = strtol(optarg, &err, 0);
			if (*err != 0) {
				fprintf(stderr, "%s: %s: invalid value for recvbuf size.\n", argv[0], optarg);
				exit(2);
			} else if (n < 1) {
				fprintf(stderr, "%s: %d: recvbuf size is out of range.\n", argv[0], n);
				exit(2);
			}
			conf->rcvbuf = n;
			break;
		case 'z':
			conf->flow_labels = 1;
			break;
		case 'g':
			conf->flow_labels = 2;
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
			break;
		case 'v':
			conf->verbose = 1;
			break;
		case '?':
		default:
			exit(2);
			break;
		}


	}

	return 0;
}

int main(int argc, char *argv[])
{
	int rv;

	struct config conf = {
		.tapdev = NULL,
		.queue = -1,
		.queue_maxlen = DEFAULT_QUEUE_MAXLEN,
		.sport = DEFAULT_PORT,
		.dport = DEFAULT_PORT,
		.key = NULL,
		.df = -1,	  /* Don't mess with DF bit */
		.dscp = -1,	  /* Don't mess with DSCP */
		.rcvbuf = -1,	  /* Don't mess with SO_RCVBUF */
		.flow_labels = 0, /* Don't mess with IPv6 if flowlabels are set */
		.verbose = 0,
	};

	parse_args(argc, argv, &conf);

	if (conf.queue > -1) {
		rv = do_nfqueue(&conf);
	} else if (conf.tapdev) {
		rv = do_tuntap(&conf);
	} else {
		fprintf(stderr, "%s: one of -q or -t must be specified.\n", conf.prog);
		exit(1);
	}

	return rv;
}

