#include <stdio.h>          /* size_t    */
#include <stdint.h>         /* [u]int*_t */
#include <netinet/ip.h>     /* iphdr     */

#ifndef _OPS_IP_H
#define _OPS_IP_H

/* individual option decoder callback array *
 * NOTE: apply 0x7f mask when calling       */
extern size_t (*ip_decoders[0x7f])(uint8_t *, size_t, uint8_t **,
    struct iphdr *, uint8_t *);

/* option processing priority */
extern uint64_t ip_ops_prio[0x7f];

#endif

