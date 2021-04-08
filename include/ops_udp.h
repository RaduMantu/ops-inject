#include <stdio.h>          /* size_t    */
#include <stdint.h>         /* [u]int*_t */
#include <netinet/ip.h>     /* iphdr     */
#include <netinet/udp.h>    /* udphdr    */

#ifndef _OPS_UDP_H
#define _OPS_UDP_H

/* individual options decoder callback array *
 * NOTE: apply 0x7f mask when calling        */
extern size_t (*udp_decoders[0xff])(uint8_t *, size_t, uint8_t **,
    struct iphdr *, uint8_t *);

/* option processing priority */
extern uint64_t udp_ops_prio[0xff];

#endif

