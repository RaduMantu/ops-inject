#include <stdio.h>          /* size_t    */
#include <stdint.h>         /* [u]int*_t */
#include <netinet/ip.h>     /* iphdr     */

#ifndef _DECODERS_H
#define _DECODERS_H

size_t decode_ip_ops(struct iphdr *iph, void **ops_buffer, uint8_t ow);
size_t decode_tcp_ops(struct iphdr *iph, void **ops_buffer, uint8_t ow);
size_t decode_udp_ops(struct iphdr *iph, void **ops_buffer, uint8_t ow);

#endif

