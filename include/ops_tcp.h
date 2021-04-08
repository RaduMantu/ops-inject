#include <stdio.h>          /* size_t    */
#include <stdint.h>         /* [u]int*_t */
#include <netinet/ip.h>     /* iphdr     */
#include <netinet/tcp.h>    /* tcphdr    */

#ifndef _OPS_TCP_H
#define _OPS_TCP_H

/* individual option decoder callback array *
 * NOTE: apply 0x7f mask when calling       */
extern size_t (*tcp_decoders[0xff])(uint8_t *, size_t, uint8_t **,
    struct iphdr *, uint8_t *);

/* option processing priority */
extern uint64_t tcp_ops_prio[0xff];

#endif

