#include <sys/time.h>       /* gettimeofday    */
#include <arpa/inet.h>      /* htonl           */
#include <string.h>         /* memset          */

#include "util.h"           /* DIE, ABORT, RET */
#include "ops_ip.h"


#define _TRACEROUTE_MODE    /* see decode_ts */


/* decode_eool - EOOL decoding callback
 *  @dst_buffer : buffer where ops are constructed before they are injected
 *  @len_left   : remaining bytes in dst_buffer
 *  @usr_ops    : reference to user specified current option
 *  @iph        : pointer to start of ip header
 *  @ops_sec    : start of temporary options buffer
 *
 *  @return : number of bytes written to dst_buffer or 0 on error
 *
 * Function must be called via the decoder callback array while masking the
 * most significant bit. usr_ops is used to correctly identify the copy bit
 * after masking but also if an experimental option needs to consume more than
 * one byte. *usr_ops is incremented according to the number of consumed bytes.
 * The ip header pointer to the yet UNMODIFIED packet is passed in case some
 * options need the information. ops_sec is passed in case the caller wishes
 * to preallocate space for the option but queues it for later computation
 * (e.g.: checksum of final options section, placed at the very start). Note
 * that any out-of-order, non-standalone option computation must be handled by
 * the caller.
 *
 * If dst_buffer is NULL, it is to be understood that the user wants to postpone
 * processing this option but wants to know the amount of space that will be
 * required. The function will modify *usr_ops and return the length as if the
 * processing has taken place. It is up to the caller to correctly interpret
 * this result.
 *
 * NOTE: this applies to all other decoders as well, but will be omitted.
 */
static size_t decode_eool(uint8_t      *dst_buffer,
                          size_t       len_left,
                          uint8_t      **usr_ops,
                          struct iphdr *iph,
                          uint8_t      *ops_sec)
{
    /* sanity checks */
    RET(!usr_ops, 0, "usr_ops is NULL");
    RET(!iph,     0, "iph is NULL");
    RET(!ops_sec, 0, "ops_sec is NULL");

    RET(len_left < 1, 0, "Not enough sapace for option");

    /* postponing processing */
    if (!dst_buffer) {
        (*usr_ops)++;
        return 1;
    } 

    /* actual processing */
    dst_buffer[0] = ((*usr_ops)++)[0];
    return 1;
}

static size_t decode_nop(uint8_t      *dst_buffer,
                         size_t       len_left,
                         uint8_t      **usr_ops,
                         struct iphdr *iph,
                         uint8_t      *ops_sec)
{
    /* sanity checks */
    RET(!usr_ops, 0, "usr_ops is NULL");
    RET(!iph,     0, "iph is NULL");
    RET(!ops_sec, 0, "ops_sec is NULL");

    RET(len_left < 1, 0, "Not enough sapace for option");

    /* postponing processing */
    if (!dst_buffer) {
        (*usr_ops)++;
        return 1;
    }

    /* actual processing */
    dst_buffer[0] = ((*usr_ops)++)[0];
    return 1; 
}

/* the initial way this was supposed to work was by adding the generating
 * host's ip:timestamp and setting the flag to 0x03, meaning that no other
 * hosts along the way could add their timestamp.
 *
 * by defining _TRACEROUTE_MODE, we make the option large enough to contain
 * the maximum number of ip:ts (4) but we don't initialize it with our own.
 * the first 4 hosts along the way will add their ip:ts and the rest will
 * increment the overflow field. if we have control of both endpoints, we
 * can determine up to 8 ip-ops knowledgeable hosts along the route.
 */
static size_t decode_ts(uint8_t      *dst_buffer,
                        size_t       len_left,
                        uint8_t      **usr_ops,
                        struct iphdr *iph,
                        uint8_t      *ops_sec)
{
    struct timestamp *ts;
    struct timeval   tv;
    uint32_t         msec;
    int              ans;

    /* sanity checks */
    RET(!usr_ops, 0, "usr_ops is NULL");
    RET(!iph,     0, "iph is NULL");
    RET(!ops_sec, 0, "ops_sec is NULL");

    /* normal mode */
#ifndef _TRACEROUTE_MODE
    RET(len_left < 12, 0, "Not enough sapace for option");

    /* postponing processing */
    if (!dst_buffer) {
        (*usr_ops)++;
        return 12;
    }

    /* get time of day for timestamp & convert it to ms since midnight in UT */
    ans = gettimeofday(&tv, NULL);
    RET(ans == -1, 0, "Unable to get time of day (%d)", errno);

    msec = (tv.tv_sec % 86400) * 1000 + tv.tv_usec / 1000;

    /* we set only one timestamp w/ associated ip address            *
     * we use flag 0x3 to prevent middleboxes from adding timestamps */
    dst_buffer[0] = ((*usr_ops)++)[0];              /* type             */
    dst_buffer[1] = 12;                             /* length           */
    dst_buffer[2] = 13;                             /* pointer          */
    dst_buffer[3] = 0x03;                           /* overflow & flags */
    *(uint32_t *)(dst_buffer + 4) = iph->saddr;     /* ip address       */
    *(uint32_t *)(dst_buffer + 8) = htonl(msec);    /* timestamp        */

    return 12;

    /* tracer mode */
#else
    RET(len_left < 36, 0, "Not enough space for option");

    /* postponing processing */
    if (!dst_buffer) {
        (*usr_ops)++;
        return 36;
    }
   
    /* skip the timestamp; allow hosts to add only ip:ts, not just ts */ 
    dst_buffer[0] = ((*usr_ops)++)[0];              /* type             */
    dst_buffer[1] = 36;                             /* length           */
    dst_buffer[2] = 5 ;                             /* pointer          */
    dst_buffer[3] = 0x03;                           /* overflow & flags */

    memset(dst_buffer + 4, 0, 32);

    return 32;
#endif
}

/* this function implements two different options:
 * 1) unkown option not assigned by IANA at this time
 *      copy=0, class=2, number=29 --> value=93 (0x5d)
 * 2) experimental option as defined in RFC4727 and recognized by IANA
 *      copy=0, class=2, number=30 --> value=94 (0x5e)
 *
 * structure:
 *      [0]  = 93 / 94
 *      [1]  = length of option (between 2 and 6)
 *      [2-] = incremental-valued bytes starting with 0
 *
 * this option SHOULD be placed last
 * fills the space with consecutively-valued bytes until the next 32b boundary
 * if start of content is already 32b aligned, 4 more bytes are added
 */
static size_t decode_unknown(uint8_t      *dst_buffer,
                             size_t       len_left,
                             uint8_t      **usr_ops,
                             struct iphdr *iph,
                             uint8_t      *ops_sec)
{
    uint8_t option_off, option_len;

    /* sanity checks */
    RET(!usr_ops, 0, "usr_ops is NULL");
    RET(!iph,     0, "iph is NULL");
    RET(!ops_sec, 0, "ops_sec is NULL");

    RET(len_left < 2, 0, "Not enough sapace for option");

    /* calculate option offset within option section *
     * if no more space, [2-] can be skipped         */
    option_off = (uint8_t) ((uint64_t) dst_buffer - (uint64_t) ops_sec);
    option_len = 4 - option_off % 4;

    if (option_len <= 2 && len_left >= 6)
        option_len += 4;

    /* postponing processing */
    if (!dst_buffer) {
        (*usr_ops)++;
        return option_len;
    }

    /* generate option content */
    *dst_buffer++ = ((*usr_ops)++)[0];
    *dst_buffer++ = option_len;
    for (uint8_t i=0; i<option_len-2; ++i)
        dst_buffer[i] = i;

    return option_len;
}

/* decode_dummy - dummy decoder for unimplemented options
 *  @return : 0
 *
 * Asking for an unimplemented option will cause this to return 0 (error) and
 * abort the option section generation. Packet should pass unmodified.
 */
static size_t decode_dummy(uint8_t      *dst_buffer,
                           size_t       len_left,
                           uint8_t      **usr_ops,
                           struct iphdr *iph,
                           uint8_t      *ops_sec)
{
    return 0;
}


/* individual option decoder callback array */
size_t (*ip_decoders[0x7f])(uint8_t *, size_t, uint8_t **,
                            struct iphdr *,  uint8_t *) = {
    [0x00 ... 0x7e] = decode_dummy,

    [0x00] = decode_eool,       /* End Of Options List */
    [0x01] = decode_nop,        /* No OPtion           */
    [0x44] = decode_ts,         /* TimeStamp           */
    [0x5d] = decode_unknown,    /* Unasigned Option    */
    [0x5e] = decode_unknown,    /* Experimental Option */
};

/* option processing priority                        *
 * NOTE: smaller value means higher priority         *
 * NOTE: a value of 0 means immediate processing     *
 * NOTE: multiple options can have the same priority */
uint64_t ip_ops_prio[0x7f] = {
    [0x00 ... 0x7e] = 0,

    [0x00] = 0,                 /* End Of Options List */
    [0x01] = 0,                 /* No OPtion           */
    [0x44] = 0,                 /* TimeStamp           */
    [0x5d] = 0,                 /* Unasigned Option    */
    [0x5e] = 0,                 /* Experimental Option */
};

