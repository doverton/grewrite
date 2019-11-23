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
#if !defined(PCAP_H)
# define PCAP_H

#define DEFAULT_PCAP_DEVICE "any"

int do_pcap(struct config *conf);

#endif

