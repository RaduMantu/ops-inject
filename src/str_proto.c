/*
 * Copyright © 2021, Radu-Alexandru Mantu <andru.mantu@gmail.com>
 *
 * This file is part of ops-inject.
 *
 * ops-inject is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * ops-inject is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with ops-inject. If not, see <https://www.gnu.org/licenses/>.
 */

#include <netinet/in.h>     /* IPPROTO_* */

#include "str_proto.h"

const char *str_ipproto[0x100] = {
    [0 ... 0xff] = "UNKNOWN PROTOCOL",

    [IPPROTO_HOPOPTS ] = "IPv6 Hop-by-Hop options",
    [IPPROTO_ICMP    ] = "Internet Control Message Protocol",
    [IPPROTO_PIM     ] = "Protocol Independent Multicast",
    [IPPROTO_COMP    ] = "Compression Header Protocol",
    [IPPROTO_PUP     ] = "PUP protocol",
    [IPPROTO_SCTP    ] = "Stream Control Transmission Protocol",
    [IPPROTO_MH      ] = "IPv6 mobility header",
    [IPPROTO_UDPLITE ] = "UDP-Lite protocol",
    [IPPROTO_MPLS    ] = "MPLS in IP",
    [IPPROTO_ETHERNET] = "Ethernet-within-IPv6 Encapsulation",
    [IPPROTO_UDP     ] = "User Datagram Protocol",
    [IPPROTO_IGMP    ] = "Internet Group Management Protocol",
    [IPPROTO_IDP     ] = "XNS IDP protocol",
    [IPPROTO_RAW     ] = "Raw IP packets",
    [IPPROTO_TP      ] = "SO Transport Protocol Class 4",
    [IPPROTO_DCCP    ] = "Datagram Congestion Control Protocol",
    [IPPROTO_IPIP    ] = "IPIP tunnels (older KA9Q tunnels use 94)",
    [IPPROTO_IPV6    ] = "IPv6 header",
    [IPPROTO_ROUTING ] = "IPv6 routing header",
    [IPPROTO_FRAGMENT] = "IPv6 fragmentation header",
    [IPPROTO_RSVP    ] = "Reservation Protocol",
    [IPPROTO_GRE     ] = "General Routing Encapsulation",
    [IPPROTO_ESP     ] = "encapsulating security payload",
    [IPPROTO_AH      ] = "authentication header",
    [IPPROTO_ICMPV6  ] = "ICMPv6",
    [IPPROTO_NONE    ] = "IPv6 no next header",
    [IPPROTO_TCP     ] = "Transmission Control Protocol",
    [IPPROTO_DSTOPTS ] = "IPv6 destination options",
    [IPPROTO_EGP     ] = "Exterior Gateway Protocol",
    [IPPROTO_MTP     ] = "Multicast Transport Protocol",
    [IPPROTO_BEETPH  ] = "IP option pseudo header for BEET",
    [IPPROTO_ENCAP   ] = "Encapsulation Header",
};

