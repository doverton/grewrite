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
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include "grewrite.h"
#include "tuntap.h"

#define TUNDEV "/dev/net/tun"
#define IP_MIN_HDR_LEN 20
#define MIN_PACKET_LEN ((ETHER_HDR_LEN) + (IP_MIN_HDR_LEN))

static int link_up(struct ifreq *ifr)
{
	int sock;
	int rv;

	if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
		return 1;

	ifr->ifr_flags |= IFF_UP;
	rv = ioctl(sock, SIOCSIFFLAGS, ifr);

	close(sock);
	return rv;
}

static int is_multicast_ether(const uint8_t *ethhdr)
{
	return *ethhdr & 1;
}

int do_tuntap(struct config *conf)
{
	int fd;
	struct ifreq ifr = { 0 };
	uint8_t buf[2048];
	uint16_t type;
	int r;
	int w;

	if ((fd = open(TUNDEV, O_RDWR)) < 0) {
		fprintf(stderr, "%s: failed to open %s: %s\n", conf->prog, TUNDEV, strerror(errno));
		exit(1);
	}

	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	strncpy(ifr.ifr_name, conf->tapdev, IFNAMSIZ);

	if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
		fprintf(stderr, "%s: %s: failed to create device: %s\n",
			conf->prog, conf->tapdev, strerror(errno));
		exit(1);
	}

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		fprintf(stderr, "%s: %s: failed to get hardware address: %s\n",
			conf->prog, conf->tapdev, strerror(errno));
		exit(1);
	}

	if (link_up(&ifr) != 0) {
		fprintf(stderr, "%s: %s: failed to enable device: %s\n",
			conf->prog, conf->tapdev, strerror(errno));
		exit(1);
	}

	while ((r = read(fd, buf, sizeof(buf))) > 0) {
		if (is_multicast_ether(buf))
			continue;

		/* We now have an ethernet frame. We only support IP at the moment */
		if ((type = ether_get_ethertype(buf)) == ETHERTYPE_IP && r >= MIN_PACKET_LEN) {
			if (transform_ip_packet(buf + ETHER_HDR_LEN, r - ETHER_HDR_LEN, conf) < 0)
				continue;
		} else {
			if (conf->verbose)
				fprintf(stderr, "%s: ignoring %d byte packet with type 0x%04x\n",
					conf->prog, r, type);
			continue;
		}

		/* Write the frame back out with own MAC address */
		ether_set_shost(buf, (uint8_t *)ifr.ifr_hwaddr.sa_data);
		if ((w = write(fd, buf, r)) != r) {
			fprintf(stderr, "%s: write to tap interface failed: %d/%d bytes written: %s\n",
				conf->prog, w, r, strerror(errno));
			break;
		}
	}

	close(fd);

	return 0;
}

