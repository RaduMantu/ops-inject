#include <stdio.h>            /* size_t                 */
#include <stdint.h>           /* [u]int*_t              */
#include <unistd.h>           /* read, geteuid          */
#include <string.h>           /* memset, memmove        */
#include <stdlib.h>           /* malloc, system, exit   */
#include <arpa/inet.h>        /* ntohl, ...             */
#include <netinet/ip.h>       /* iphdr                  */
#include <netinet/tcp.h>      /* tcphdr                 */
#include <netinet/udp.h>      /* udphdr                 */

#include <stdbool.h>          /* fixes pktbuff.h error  */
#include <linux/netfilter.h>  /* NF_ACCEPT              */
#include <libnetfilter_queue/libnetfilter_queue.h>

/* prefer writing these in C due to Designated Initializers *
 * makes the usage of callback arrays more pleasant         */
extern "C" {
#include "csum.h"             /* checksum functions     */
}
#include "cli_args.h"         /* argument parsing       */
#include "util.h"             /* DIE, ABORT, RET        */


/* annotator - callback routine for NetfilterQueue
 *  @qh    : netfilter queue handle
 *  @nfmsg : general form of address family dependent message
 *  @nfd   : nfq related data for packet evaluation
 *  @data  : data parameter passed unchanged by nfq_create_queue()
 *           here, NULL
 *
 *  @return : 0 if ok, -1 on error (handled by nfq_set_verdict())
 */
int annotator(struct nfq_q_handle *qh,
              struct nfgenmsg     *nfmsg,
              struct nfq_data     *nfd,
              void                *data)
{
    static uint8_t              mod_buffer[0xffff]; /* modified packet     */
    struct nfqnl_msg_packet_hdr *ph;                /* nfq meta header     */
    struct iphdr                *iph;               /* ip header           */
    struct iphdr                *mod_iph;           /* modified packet hdr */
    uint8_t                     *ops_buffer;        /* complete ops buffer */
    size_t                      ops_len;            /* complete ops length */
    int                         ans;

    /* get nfq packet header (w/ metadata) */
    ph = nfq_get_msg_packet_hdr(nfd);
    RET(!ph, -1, "Unable to retrieve packet meta hdr (%d)", errno);

    /* extract raw packet */
    ans = nfq_get_payload(nfd, (uint8_t **) &iph);
    RET(ans == -1, -1, "Unable to retrieve packet data (%d)", errno);
    RET(ans != ntohs(iph->tot_len), -1, "Payload size & total len mismatch");

    /* decode protocol specific ops (may depend on packet contents)         *
     * NOTE: 0 len may mean that an error has occurred and will be reported *
     *       by the decoder or that the target protcol was not found in the *
     *       captured packet; for the latter case, refine the iptables rule */
    ops_len = args.decoder(iph, (void **) &ops_buffer, args.overwrite);
    ABORT(!ops_len, pass_unchanged, "Decoding failed");

    /* reassemble the packet by incorporating the decoded options */ 
    ans = args.reasmbl(iph, mod_buffer, ops_buffer, ops_len, args.overwrite);
    ABORT(ans, pass_unchanged, "Reassembly failed");

    /* recalculate layer 4 and layer 3 checksums for updated content          *
     * NOTE: even if a layer 4 protocol does not require checksum calculation *
     *       it should still have a 'return 0' callback                       */
    mod_iph = (struct iphdr *) mod_buffer;
    ans = layer4_csum[mod_iph->protocol](mod_iph);
    ABORT(ans, pass_unchanged, "Layer 4 checksum failed");

    ans = ipv4_csum(mod_iph);
    ABORT(ans, pass_unchanged, "Layer 3 checksum failed");

    /* in case of filter chaining */
    if (args.redirect)
        goto redirect;

    /* set verdict */
pass_changed:
    return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT,
        ntohs(mod_iph->tot_len), mod_buffer);
pass_unchanged:
    return nfq_set_verdict(qh, ntohl(ph->packet_id), NF_ACCEPT, 0, NULL);
redirect:
    return nfq_set_verdict(qh, ntohl(ph->packet_id),
        (args.nq_num << 16) | NF_QUEUE, ntohs(mod_iph->tot_len), mod_buffer);
}

/* main - program entry point
 *  @argc : number of command line arguments
 *  @argv : array of command line arguments
 *
 *  @return : exit status
 */
int main(int argc, char **argv)
{
    struct nfq_handle   *h  = NULL;
    struct nfq_q_handle *qh = NULL;
    uint8_t             buffer[0xffff];
    int                 ans, fd;

    /* check effective user id */
    DIE(geteuid(), "Please run as root");

    /* parse command line argumnets */
    argp_parse(&argp, argc, argv, 0, 0, &args);
    DIE(!args.ops, "No user options provided");
    DIE(!args.ops_len, "User options have length 0");

    /* open nfq handle */
    h = nfq_open();
    DIE(!h, "Unable to open nfq handle (%d)", errno); 
    
    /* bind nfq handle to queue */
    qh = nfq_create_queue(h, args.q_num, annotator, NULL);
    ABORT(ans < 0, cleanup_handle, "Unable to create a queue (%d)", errno);

    /* set the amount of data to be copied to userspace (max ip packet size) */
    ans = nfq_set_mode(qh, NFQNL_COPY_PACKET, sizeof(buffer));
    ABORT(ans < 0, cleanup_queue, "Unable to set mode (%d)", errno);

    /* obtain fd of queue handle's associated socket */
    fd = nfq_fd(h);

    /* read packets into userspace buffer & invoke callback */
    while (ans = read(fd, buffer, sizeof(buffer))) {
        ABORT(ans < 0, cleanup_queue, "Error reading from socket (%d)", errno);

        nfq_handle_packet(h, (char *) buffer, ans);
    }

cleanup_queue:
    nfq_destroy_queue(qh);
cleanup_handle:
    nfq_close(h);

    return 0;
}

