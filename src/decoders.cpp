#include <stdio.h>          /* size_t    */
#include <stdint.h>         /* [u]int*_t */
#include <string.h>         /* memset    */
#include <arpa/inet.h>      /* ntohs     */
#include <netinet/ip.h>     /* iphdr     */
#include <netinet/tcp.h>    /* tcphdr    */
#include <netinet/udp.h>    /* udphdr    */

#include <queue>            /* priority queue */
#include <tuple>            /* tuple          */
#include <vector>           /* vector         */

extern "C" {
#include "ops_ip.h"         /* individual ip  options decoders */
#include "ops_tcp.h"        /* individual tcp options decoders */
#include "ops_udp.h"        /* individual udp options decoders */
}

#include "cli_args.h"       /* args (after processing) */
#include "util.h"           /* DIE, ABORT, RET         */
#include "decoders.h"

using namespace std;

/* create alias for post processing data        *
 *      <0> : destination of processed option   *
 *      <1> : length of promised option         *
 *      <2> : pointer to user's type request    */
typedef tuple<uint8_t *, size_t, uint8_t *> pp_data;


/* decode_ip_ops - generate options section based on user's requested ops
 *  @iph        : start of ip header
 *  @ops_buffer : address of a pointer used to indicate generated ops buffer
 *                location to the caller; buffer becomes invalid after a
 *                subsequent call to this function
 *  @ow         : 0 if not overwriting existing options
 *
 *  @return : len of ops section buffer (is multiple of 4 bytes) or 0 on failure
 *            (adding ops may cause fragmentation or exceed ops length limit)
 *
 * NOTE: the caller must remove any previous EOOL, recompose the packet,
 *       recalculate total length and checksum
 */
size_t decode_ip_ops(struct iphdr *iph, void **ops_buffer, uint8_t ow)
{
    /* ip options size limit is 40 bytes (4 bit IHL) */
    static uint8_t  ops[40];
    size_t          len_left   = 0;     /* space left for options        */
    size_t          padded_len = 0;     /* length of options w/  padding */
    size_t          len        = 0;     /* length of options w/o padding */
    size_t          ans;
    uint8_t         *aux;

    /* priority queue holding delayed option processing requests */
    auto compare = [](pp_data lhs, pp_data rhs)
    {
        return ip_ops_prio[*get<2>(lhs) & 0x7f] > 
               ip_ops_prio[*get<2>(rhs) & 0x7f];
    };
    priority_queue<pp_data, vector<pp_data>, decltype(compare)> pq(compare);

    /* sanity checks */
    RET(!iph,         0, "iph is NULL");
    RET(!ops_buffer,  0, "ops_buffer is NULL");

    /* check protocol */
    RET(iph->version != 4, 0, "Layer 3 protocol mismatch");

    /* calculate remaining length in header */
    len_left = (0x0f - (ow ? 5 : iph->ihl)) * 4;

    /* perform decoding */
    for (uint8_t *it = args.ops; it < args.ops + args.ops_len; len += ans) {
        /* immediate processing */
        if (!ip_ops_prio[*it & 0x7f]) {
            ans = ip_decoders[*it & 0x7f](ops + len, len_left - len, &it, iph, ops);
            RET(!ans, 0, "Unable to decode byte %lu of user ops",
                (unsigned long)(it - args.ops));
        }
        /* delayed processing */
        else {
            /* save ptr to current user option before being incremented */
            aux = it;

            /* request space estimate */
            ans = ip_decoders[*it & 0x7f](NULL, len_left - len, &it, iph, ops);
            RET(!ans, 0, "Unable to decode byte %lu of user ops",
                (unsigned long)(it - args.ops));

            /* enqueue request */
            pq.push(make_tuple(ops + len, ans, aux));
        }
    }

    /* perform delayed decoding */
    while (!pq.empty()) {
        auto [delayed_dst, delayed_len, delayed_op] = pq.top();
        pq.pop();

        /* consider more than enough length left (already checked before) */
        ans = ip_decoders[*delayed_op & 0x7f](delayed_dst, 0xffff, &delayed_op,
                iph, ops);
        RET(!ans, 0, "Unable to decode byte %lu of user ops",
            (unsigned long)(delayed_op - args.ops));
    }

    /* calculate padded length (must be multiple of 4 for ihl) */
    padded_len  = len & ~0x03L;
    padded_len += !!(len & 0x03) * 4;
    
    /* set padding (if needed) */
    memset(ops + len, 0, padded_len - len);

    /* return reference to options buffer and length of (padded) buffer */
    *ops_buffer = &ops;
    return padded_len;
}

/* decode_tcp_ops - generate options section based on user's requested ops
 *  @iph        : start of ip header
 *  @ops_buffer : address of a pointer used to indicate generated ops buffer
 *                location to the caller; buffer becomes invalid after a
 *                subsequent call to this function
 *  @ow         : 0 if not overwriting existing options
 *
 *  @return : len of ops section buffer (is multiple of 4 bytes) or 0 on failure
 *            (adding ops may cause fragmentation or exceed ops length limit)
 *
 * NOTE: the caller must remove any previous EOOL, recompose the packet,
 *       recalculate data offset and checksum
 */
size_t decode_tcp_ops(struct iphdr *iph, void **ops_buffer, uint8_t ow)
{
    /* tcp options size limit is 40 bytes (4 bit Data Offset) */
    static uint8_t  ops[40];
    size_t          len_left   = 0;     /* space left for options        */
    size_t          padded_len = 0;     /* length of options w/  padding */
    size_t          len        = 0;     /* length of options w/o padding */
    size_t          ans;
    uint8_t         *aux;
    struct tcphdr*  tcph;   

    /* priority queue holding delayed option processing requests */
    auto compare = [](pp_data lhs, pp_data rhs)
    {
        return tcp_ops_prio[*get<2>(lhs) & 0x7f] >
               tcp_ops_prio[*get<2>(rhs) & 0x7f];
    };
    priority_queue<pp_data, vector<pp_data>, decltype(compare)> pq(compare);

    /* sanity checks */
    RET(!iph,         0, "iph is NULL");
    RET(!ops_buffer,  0, "ops_buffer is NULL");

    /* check protocol */ 
    RET(iph->version  != 4, 0, "Layer 3 protocol mismatch");
    RET(iph->protocol != 6, 0, "Layer 4 protocol mismatch");

    /* extract tcp header */
    tcph = (struct tcphdr *)(((uint8_t *) iph) + iph->ihl * 4);

    /* calculate remaining length in header */
    len_left = (0x0f - (ow ? 5 : tcph->doff)) * 4;

    /* perform decoding */
    for (uint8_t *it = args.ops; it < args.ops + args.ops_len; len += ans) {
        /* immediate processing */
        if (!tcp_ops_prio[*it & 0x7f]) {
            ans = tcp_decoders[*it & 0x7f](ops + len, len_left - len, &it,
                    iph, ops);
            RET(!ans, 0, "Unable to decode byte %lu of user ops",
                (unsigned long)(it - args.ops));
        }
        /* delayed processing */
        else {
            /* save ptr to current user option before being incremented */
            aux = it;

            /* request space estimate */
            ans = tcp_decoders[*it & 0x7f](NULL, len_left - len, &it, iph, ops);
            RET(!ans, 0, "Unable to decode byte %lu of user ops",
                (unsigned long)(it - args.ops));

            /* enqueue request */
            pq.push(make_tuple(ops + len, ans, aux));
        }
    }

    /* perform delayed decoding */
    while (!pq.empty()) {
        auto [delayed_dst, delayed_len, delayed_op] = pq.top();
        pq.pop();

        /* consider more than enough length left (already checked before) */
        ans = tcp_decoders[*delayed_op & 0x7f](delayed_dst, 0xffff, &delayed_op,
                iph, ops);
        RET(!ans, 0, "Unable to decode byte %lu of user ops",
            (unsigned long)(delayed_op - args.ops));
    } 

    /* calculate padded length (must be multiple of 4 for doff) */
    padded_len  = len & ~0x03L;
    padded_len += !!(len & 0x03) * 4;

    /* set padding if needed */
    memset(ops + len, 0, padded_len - len);

    /* return references to options buffer and length of padded buffer */
    *ops_buffer = &ops;
    return padded_len;
}

/* decode_udp_ops - generate options section based on user's requested ops
 *  @iph        : start of ip header
 *  @ops_buffer : address of a pointer used to indicate generated ops buffer
 *                location to the caller; buffer becomes invalid after a
 *                subsequent call to this function 
 *  @ow         : 0 if not overwriting existing options
 *
 *  @return : len of ops section buffer (is multiple of 4 bytes) or 0 on failure
 *            (adding ops may cause fragmentation or exceed ops length limit)
 *
 * NOTE: the caller must remove any previous EOOL, recompose the packet,
 *       recalculate data offset and checksum
 */
size_t decode_udp_ops(struct iphdr *iph, void **ops_buffer, uint8_t ow)
{
    /* udp options size limit is determined by packet length */
    static uint8_t  ops[0xffff];
    size_t          len_left   = 0;     /* space left for options        */
    size_t          len        = 0;     /* length of options w/o padding */
    size_t          ans;
    struct udphdr   *udph;
    uint8_t         *aux;

    /* priority queue holding delayed option processing requests */
    auto compare = [](pp_data lhs, pp_data rhs)
    {
        return udp_ops_prio[*get<2>(lhs) & 0x7f] > 
               udp_ops_prio[*get<2>(rhs) & 0x7f];
    };
    priority_queue<pp_data, vector<pp_data>, decltype(compare)> pq(compare);

    /* sanity checks */
    RET(!iph,         0, "iph is NULL");
    RET(!ops_buffer,  0, "ops_buffer is NULL");

    /* check protocol */
    RET(iph->version  != 4,  0, "Layer 3 protocol mismatch");
    RET(iph->protocol != 17, 0, "Layer 4 protocol mismatch");

    /* extract udp header */
    udph = (struct udphdr *)(((uint8_t *) iph) + iph->ihl * 4);
 
    /* calculate remaining length for options */
    len_left = sizeof(ops) - (ow ? iph->ihl * 4 + ntohs(udph->len) :
        ntohs(iph->tot_len));

    /* perform decoding */
    for (uint8_t *it = args.ops; it < args.ops + args.ops_len; len += ans) {
        /* immediate processing */
        if (!udp_ops_prio[*it & 0x7f]){
            ans = udp_decoders[*it & 0x7f](ops + len, len_left - len, &it,
                    iph, ops);
            RET(!ans, 0, "Unable to decode byte %lu of user ops",
                (unsigned long)(it - args.ops));
        }
        /* delayed processing */
        else {
            /* save ptr to current user option before being incremented */
            aux = it;

            /* request space estimation */
            ans = udp_decoders[*it & 0x7f](NULL, len_left - len, &it, iph, ops);
            RET(!ans, 0, "Unable to decode byte %lu of user ops",
                (unsigned long)(it - args.ops));

            /* enqueue request */
            pq.push(make_tuple(ops + len, ans, aux));
        }
    }

    /* perform delayed decoding */
    while (!pq.empty()) {
        auto [delayed_dst, delayed_len, delayed_op] = pq.top();
        pq.pop();

        printf(">>> %02hhx\n", *delayed_op);

        /* consider more than enough length left (already checked before) */
        ans = udp_decoders[*delayed_op & 0x7f](delayed_dst, 0xffff, &delayed_op,
                iph, ops);
        RET(!ans, 0, "Unable to decode byte %lu of user ops",
            (unsigned long)(delayed_op - args.ops));
    }

    /* no padding needed (length not expressed in dwords)       *
     * return references to options buffer and length of buffer */
    *ops_buffer = &ops;
    return len;
}

