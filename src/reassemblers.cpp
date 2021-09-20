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

#include <stdio.h>          /* size_t       */
#include <stdint.h>         /* [u]int*_t    */
#include <string.h>         /* memcpy       */
#include <arpa/inet.h>      /* htons, ntohs */
#include <netinet/ip.h>     /* iphdr        */
#include <netinet/tcp.h>    /* tcphdr       */
#include <netinet/udp.h>    /* udphdr       */

#include "util.h"           /* DIE, ABORT, RET */
#include "reassemblers.h"

/* reassemble_ip - creates a new packet by including generated options
 *  @iph      : ip header
 *  @mod_buff : modified buffer (should be 0xffff bytes in size)
 *  @ops      : options buffer (populated by decoder)
 *  @ops_len  : options length (padding included)
 *  @ow       : 0 if not overwriting existing options
 *
 *  @return : 0 if everything went ok
 *
 * This function is not responsible for recalculating checksums. This process
 * is independent of the annotated protocol and should be treated on a
 * case-by-case basis (e.g.: ip options change ip.tot_len which changes tcp
 * checksum). All other fields will be properly set in this function.
 */
int reassemble_ip(struct iphdr *iph, uint8_t *mod_buff, uint8_t *ops,
    size_t ops_len, uint8_t ow)
{
    size_t  new_len   = 0;                  /* offset in new buffer    */
    size_t  offset    = 0;                  /* offset in source buffer */
    size_t  aux_len   = 0;                  /* avoid recalculations    */
    uint8_t *src_buff = (uint8_t *) iph;    /* easier access           */
    int     ans;

    /* sanity checks */
    RET(!iph,      1, "iph is NULL");
    RET(!mod_buff, 1, "mod_buff is NULL");
    RET(!ops,      1, "ops is NULL");

    /* copy base ip header */
    memcpy(mod_buff, src_buff, 20);
    new_len = 20;
    offset  = 20;
    
    /* copy existing ip options (if any) */
    if (!ow) {
        memcpy(mod_buff + new_len, src_buff + offset, iph->ihl * 4 - 20);
        new_len = iph->ihl * 4;
    }
    offset = iph->ihl * 4;

    /* copy new options */
    memcpy(mod_buff + new_len, ops, ops_len);
    new_len += ops_len;

    /* copy data */
    aux_len = ntohs(iph->tot_len) - iph->ihl * 4;
    memcpy(mod_buff + new_len, src_buff + offset, aux_len);
    new_len += aux_len;
    
    /* set fields for new packet */
    iph = (struct iphdr *) mod_buff;
    iph->tot_len = htons((uint32_t) new_len);
    iph->ihl = (ow ? 5 : iph->ihl) + ops_len / 4;

    return 0;
}

/* reassemble_tcp - creates a new packet by including generated options
 *  @iph      : ip header
 *  @mod_buff : modified buffer (should be 0xffff bytes in size)
 *  @ops      : options buffer (populated by decoder)
 *  @ops_len  : options length (padding included)
 *  @ow       : 0 if not overwriting existing options
 *
 *  @return : 0 if everything went ok
 *
 * This function is not responsible for recalculating checksums. This process
 * is independent of the annotated protocol and should be treated on a
 * case-by-case basis. All other fields will be properly set in this function.
 */
int reassemble_tcp(struct iphdr *iph, uint8_t *mod_buff, uint8_t *ops,
    size_t ops_len, uint8_t ow)
{
    size_t        new_len   = 0;                /* offset in new buffer    */
    size_t        offset    = 0;                /* offset in source buffer */
    size_t        aux_len   = 0;                /* avoid recalculations    */
    uint8_t       *src_buff = (uint8_t *) iph;  /* easier access           */
    struct tcphdr *tcph     = (struct tcphdr *)(src_buff + iph->ihl * 4);
    int           ans;

    /* sanity checks */
    RET(!iph,      1, "iph is NULL");
    RET(!mod_buff, 1, "mod_buff is NULL");
    RET(!ops,      1, "ops is NULL");

    /* copy ip header (and options, if any) */
    memcpy(mod_buff, src_buff, iph->ihl * 4);
    new_len = iph->ihl * 4;
    offset  = iph->ihl * 4;

    /* copy base tcp header */
    memcpy(mod_buff + new_len, src_buff + offset, 20);
    new_len += 20;
    offset  += 20;

    /* copy existing tcp options (if any) */
    aux_len = tcph->doff * 4 - 20;
    if (!ow) {
        memcpy(mod_buff + new_len, src_buff + offset, aux_len);
        new_len += aux_len;
    }
    offset += aux_len;

    /* copy new options */
    memcpy(mod_buff + new_len, ops, ops_len);
    new_len += ops_len;

    /* copy data */
    aux_len = ntohs(iph->tot_len) - (iph->ihl + tcph->doff) * 4;
    memcpy(mod_buff + new_len, src_buff + offset, aux_len);
    new_len += aux_len;

    /* set fields for new packet */
    iph  = (struct iphdr *) mod_buff;
    tcph = (struct tcphdr *)(mod_buff + iph->ihl * 4);
    iph->tot_len = htons((uint32_t) new_len);
    tcph->doff = (ow ? 5 : tcph->doff) + ops_len / 4;

    return 0;
}

/* reassemble_udp - creates a new packet by including generated options
 *  @iph      : ip header
 *  @mod_buff : modified buffer (should be 0xffff bytes in size)
 *  @ops      : options buffer (populated by decoder)
 *  @ops_len  : options length (padding included)
 *  @ow       : 0 if not overwriting existing options
 *
 *  @return : 0 if everything went ok
 *
 * This function is not responsible for recalculating checksums. This process
 * is independent of the annotated protocol and should be treated on a
 * case-by-case basis. All other fields will be properly set in this function.
 */
int reassemble_udp(struct iphdr *iph, uint8_t *mod_buff, uint8_t *ops,
    size_t ops_len, uint8_t ow)
{
    size_t        new_len   = 0;                /* offset in new buffer    */
    size_t        offset    = 0;                /* offset in source buffer */
    size_t        aux_len   = 0;                /* avoid recalculations    */
    uint8_t       *src_buff = (uint8_t *) iph;  /* easier access           */
    struct udphdr *udph     = (struct udphdr *)(src_buff + iph->ihl * 4);
    int           ans;

    /* sanity checks */
    RET(!iph,      1, "iph is NULL");
    RET(!mod_buff, 1, "mod_buff is NULL");
    RET(!ops,      1, "ops is NULL");

    /* copy ip header (and options, if any) */
    memcpy(mod_buff, src_buff, iph->ihl * 4);
    new_len = iph->ihl * 4;
    offset  = iph->ihl * 4;

    /* copy udp header (has no options) */
    memcpy(mod_buff + new_len, src_buff + offset, 8);
    new_len += 8;
    offset  += 8;

    /* copy data */
    aux_len = ntohs(udph->len) - 8;
    memcpy(mod_buff + new_len, src_buff + offset, aux_len);
    new_len += aux_len;
    offset  += aux_len;

    /* copy existing udp options (if any) */
    if (!ow) {
        aux_len = ntohs(iph->tot_len) - ntohs(udph->len);
        memcpy(mod_buff + new_len, src_buff + offset, aux_len);
        new_len += aux_len;
    }
    
    /* copy new options */
    memcpy(mod_buff + new_len, ops, ops_len);
    new_len += ops_len;

    /* set fields for new packet */
    iph = (struct iphdr *) mod_buff;
    iph->tot_len = htons((uint32_t) new_len);

    return 0;
}

