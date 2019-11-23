/*
 * (C) 2017-2019 David Overton <david@insomniavisions.com>
 *
 * This file is part of grewrite.
 *
 * grewrite is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * grewrite is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with grewrite.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <pcap/sll.h>
#include "grewrite.h"
#include "pcap.h"

#define PCAP_TIMEOUT 1000

static uint16_t sll_get_packet_type(const uint8_t *sllhdr);
static uint16_t sll_get_arphrd_type(const uint8_t *sllhdr);
static uint16_t sll_get_proto(const uint8_t *sllhdr);
static void setup_signals(void);
static void on_signal(int sig);

static int killswitch = -1;

int do_pcap(struct config *conf)
{
	pcap_t *pcap;
	pcap_dumper_t *dump;
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const uint8_t *packet;
	uint8_t buf[2048];
	int result;
	int linktype;

	if (killswitch != -1) {
		fprintf(stderr, "%s: do_pcap() is not reetntrant.\n",
				conf->prog);
		return 1;
	} else {
		setup_signals();
		killswitch = 0;
	}

	if (conf->pcap[0] == '.' || conf->pcap[0] == '/') {
		if ((pcap = pcap_open_offline(conf->pcap, pcap_errbuf)) == NULL) {
			fprintf(stderr, "%s: %s: failed to open capture file: %s\n",
					conf->prog, conf->pcap, pcap_errbuf);
			exit(1);
		}
	} else {
		if ((pcap = pcap_open_live(conf->pcap, 0, 0, PCAP_TIMEOUT, pcap_errbuf)) == NULL) {
			fprintf(stderr, "%s: %s: failed to start capture: %s\n",
					conf->prog, conf->pcap, pcap_errbuf);
			exit(1);
		}
	}

	linktype = pcap_datalink(pcap);
	if (linktype != DLT_EN10MB && linktype != DLT_LINUX_SLL) {
		fprintf(stderr, "%s: %s: link type %d is not supported\n",
				conf->prog, conf->pcap, linktype);
		exit(1);
	}

	if ((dump = pcap_dump_fopen(pcap, stdout)) == NULL) {
		fprintf(stderr, "%s: failed to open stdout as dump file\n",
				conf->prog);
		exit(1);
	}

	while (!killswitch) {
		if ((result = pcap_next_ex(pcap, &header, &packet)) < 0)
			break;
		else if (result == 0)
			continue;

		if (linktype == DLT_EN10MB
				&& ether_get_ethertype(packet) == ETHERTYPE_IP
				&& ip_get_version(packet + ETHER_HDR_LEN) == 4) {

			memcpy(buf, packet, header->caplen);
			if (transform_ip_packet(buf + ETHER_HDR_LEN, header->caplen, conf) == 0)
				packet = buf;
		} else if (linktype == DLT_LINUX_SLL
				&& sll_get_packet_type(packet) == LINUX_SLL_HOST
				&& sll_get_arphrd_type(packet) == ARPHRD_ETHER
				&& sll_get_proto(packet) == ETHERTYPE_IP) {

			memcpy(buf, packet, header->caplen);
			if (transform_ip_packet(buf + SLL_HDR_LEN, header->caplen, conf) == 0)
				packet = buf;
		}

		pcap_dump((uint8_t *)dump, header, packet);
	}

	pcap_dump_close(dump);
	pcap_close(pcap);

	killswitch = -1;
	return 0;
}

static uint16_t sll_get_packet_type(const uint8_t *sllhdr)
{
	return ntohs(*(const uint16_t *)(sllhdr));
}

static uint16_t sll_get_arphrd_type(const uint8_t *sllhdr)
{
	return ntohs(*(const uint16_t *)(sllhdr + 2));
}

static uint16_t sll_get_proto(const uint8_t *sllhdr)
{
	return ntohs(*(const uint16_t *)(sllhdr + 14));
}

static void setup_signals(void)
{
	struct sigaction act;

	act.sa_handler = on_signal;
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);

	sigaction(SIGINT, &act, NULL);
	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
}

static void on_signal(int sig)
{
	killswitch = 1;
}

