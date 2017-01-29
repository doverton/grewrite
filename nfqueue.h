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
#if !defined(NFQUEUE_H)
# define NFQUEUE_H

#define NF_PREROUTING 0
#define NF_POSTROUTING 4

#define DEFAULT_QUEUE_NUM 65109
#define DEFAULT_QUEUE_MAXLEN 4096

int do_nfqueue(struct config *conf);

#endif

