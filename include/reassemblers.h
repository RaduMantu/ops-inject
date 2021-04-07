#include <stdio.h>      /* size_t    */
#include <stdint.h>     /* [u]int*_t */
#include <netinet/ip.h> /* iphdr     */

#ifndef _REASSEMBLERS_H
#define _REASSEMBLERS_H

int reassemble_ip(struct iphdr *iph, uint8_t *mod_buff, uint8_t *ops,
    size_t ops_len, uint8_t ow);
int reassemble_tcp(struct iphdr *iph, uint8_t *mod_buff, uint8_t *ops,
    size_t ops_len, uint8_t ow);
int reassemble_udp(struct iphdr *iph, uint8_t *mod_buff, uint8_t *ops,
    size_t ops_len, uint8_t ow);

#endif
