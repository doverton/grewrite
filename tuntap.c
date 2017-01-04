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
		fprintf(stderr, "%s: %s: failed to get hardwareaddress: %s\n",
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
		if ((type = ether_get_ethertype(buf)) == ETHERTYPE_IP && r >= 34) {
			transform_ip_packet(buf + 14, r - 14, conf);
		} else {
			if (conf->verbose)
				fprintf(stderr, "%s: ignoring %d byte packet with type 0x%04x\n",
					conf->prog, r, type);
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

