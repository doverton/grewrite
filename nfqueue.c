/*
 * (C) 2017 David Overton <david@insomniavisions.com>
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
#include <net/ethernet.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "grewrite.h"

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *ptr)
{
	struct config *conf = ptr;
	uint8_t *data = NULL;
	size_t size = 0;

	struct nfqnl_msg_packet_hdr *ph;
	uint16_t type;

	if ((ph = nfq_get_msg_packet_hdr(nfa)) == NULL) {
		fprintf(stderr, "bad packet?\n");
		return -1;
	}

	type = ntohs(ph->hw_protocol);

	if (type == ETHERTYPE_IP && (size = nfq_get_payload(nfa, &data)) >= 20) {
		if (transform_ip_packet(data, size, conf) != 0) {
			data = NULL;
			size = 0;
		}
	} else {
		if (conf->verbose)
			fprintf(stderr, "%s: ignoring %zu byte packet with type 0x%04x\n", conf->prog, size, type);
	}

	return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, size, data);
}

int do_nfqueue(struct config *conf)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	char buf[4096] __attribute__ ((aligned));
	int rv;
	int fd;

	if ((h = nfq_open()) == NULL) {
		fprintf(stderr, "%s: failed to open nfq\n", conf->prog);
		exit(1);
	}

	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "%s: failed to bind for AF_NET: %s\n", conf->prog, strerror(errno));
		exit(1);
	}

	if ((qh = nfq_create_queue(h, conf->queue, cb, conf)) == NULL) {
		fprintf(stderr, "%s: failed to create queue", conf->prog);
		exit(1);
	}

	if (nfq_set_queue_maxlen(qh, conf->queue_maxlen) < 0) {
		fprintf(stderr, "%s: failed to set queue length", conf->prog);
		exit(1);
	}

	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "%s: failed to set copy packet mode\n", conf->prog);
		exit(1);
	}

	fd = nfq_fd(h);

	if (conf->rcvbuf > -1) {
		int rcvbuf = conf->rcvbuf;
		socklen_t len = sizeof(rcvbuf);

		if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, len) < 0) {
			fprintf(stderr, "%s: failed to set receive buffer size\n", conf->prog);
			exit(1);
		}
		if (conf->verbose && getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, &len) == 0) {
			if (rcvbuf / 2 < conf->rcvbuf) {
				fprintf(stderr, "%s: receive buffer size was capped to %d, ", conf->prog, rcvbuf / 2);
				fprintf(stderr, "increase this by running:\n\n");
				fprintf(stderr, "    sysctl net.core.rmem_max=%d\n\n", conf->rcvbuf);
			}
		}
	}

	while (1) {
		while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0)
			nfq_handle_packet(h, buf, rv);
		if (errno != ENOBUFS) {
			if (conf->verbose)
				fprintf(stderr, "%s: out of buffer space, ignoring.\n", conf->prog);
		} else {
			break;
		}
	}
	if (errno != 0)
		fprintf(stderr, "%s: failed to recv: %s\n", conf->prog, strerror(errno));

	nfq_destroy_queue(qh);
	nfq_close(h);

	return 0;
}

