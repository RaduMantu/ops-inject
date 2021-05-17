#include <sys/time.h>       /* gettimeofday    */
#include <arpa/inet.h>      /* htonl           */

#include "util.h"           /* DIE, ABORT, RET */
#include "ops_tcp.h"


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
static size_t decode_eool(uint8_t       *dst_buffer,
                          size_t        len_left,
                          uint8_t       **usr_ops,
                          struct iphdr  *iph,
                          uint8_t       *ops_sec)
{
    /* sanity checks */
    RET(!usr_ops, 0, "usr_ops is NULL");
    RET(!iph,     0, "iph is NULL");
    RET(!ops_sec, 0, "ops_sec is NULL");

    RET(len_left < 1, 0, "Not enough space for option");

    /* postponing processing */
    if (!dst_buffer) {
        (*usr_ops)++;
        return 1;
    }

    /* actual processing */
    dst_buffer[0] = ((*usr_ops)++)[0];
    return 1;
}

static size_t decode_nop(uint8_t        *dst_buffer,
                         size_t         len_left,
                         uint8_t        **usr_ops,
                         struct iphdr   *iph,
                         uint8_t        *ops_sec)
{
    /* sanity checks */
    RET(!usr_ops, 0, "usr_ops is NULL");
    RET(!iph,     0, "iph is NULL");
    RET(!ops_sec, 0, "ops_sec is NULL");

    RET(len_left < 1, 0, "Not enough space for option");

    /* postponing processing */
    if (!dst_buffer) {
        (*usr_ops)++;
        return 1;
    }

    /* actual processing */
    dst_buffer[0] = ((*usr_ops)++)[0];
    return 1;
}

/* obsoleted in RFC6247                                                *
 * this function implements both echo (kind=6) and echo reply (kind=7) */
static size_t decode_echo_reply(uint8_t       *dst_buffer,
                                size_t        len_left,
                                uint8_t       **usr_ops,
                                struct iphdr  *iph,
                                uint8_t       *ops_sec)
{
    /* sanity checks */
    RET(!usr_ops, 0, "usr_ops is NULL");
    RET(!iph,     0, "iph is NULL");
    RET(!ops_sec, 0, "ops_sec is NULL");

    RET(len_left < 6, 0, "Not enough space for option");

    /* postponing processing */
    if (!dst_buffer) {
        (*usr_ops)++;
        return 6;
    }

    /* echoed value should be timestamp; place dummy value */
    dst_buffer[0] = ((*usr_ops)++)[0];                  /* kind         */
    dst_buffer[1] = 6;                                  /* length       */
    *(uint32_t *) &dst_buffer[2] = htonl(0x01020304);   /* echoed value */

    return 6;
}

static size_t decode_ts(uint8_t         *dst_buffer,
                        size_t          len_left,
                        uint8_t         **usr_ops,
                        struct iphdr    *iph,
                        uint8_t         *ops_sec)
{
    struct timeval  tv;
    struct tcphdr   *tcph;
    int             ans;

    /* sanity checks */
    RET(!usr_ops, 0, "usr_ops is NULL");
    RET(!iph,     0, "iph is NULL");
    RET(!ops_sec, 0, "ops_sec is NULL");

    RET(len_left < 10, 0, "Not enough space for option");

    /* postponing processing */
    if (!dst_buffer) {
        (*usr_ops)++;
        return 10;
    }

    /* get time of day for timestamp                                    *
     * NOTE: unlike ip timestamps, we only care that it's monotonically *
             non-decreasing in time                                     */
    ans = gettimeofday(&tv, NULL);
    RET(ans == -1, 0, "Unable to get time of day (%d)", errno);

    /* get tcp header */
    tcph = (struct tcphdr *)(((uint8_t *) iph) + iph->ihl * 4);

    /* TSecr = 0         if ACK=0 ; TSval is generated ts *
     * TSval = TSecr + 1 if ACK=1 ; TSecr is generated ts */
    dst_buffer[0] = ((*usr_ops)++)[0];  /* kind   */
    dst_buffer[1] = 10;                 /* length */
    *(uint32_t *)(dst_buffer + 2) = htonl((uint32_t) tv.tv_sec + tcph->ack * 100);
    *(uint32_t *)(dst_buffer + 6) = htonl((uint32_t) tv.tv_sec * tcph->ack);

    return 10;
}

/* this function provides an arbitrary implementation of a IANA reserved TCP
 * option that is not in use at this time
 *      kind=71 (0x47)
 *
 * structure:
 *      [0]  = 71
 *      [1]  = length of option (between 2 and 6)
 *      [2-] = incremental-valued bytes starting with 0
 *
 * fills the space with consecutively-valued bytes until the next 32b boundary
 * if start of content is already 32b aligned, 4 more bytes are added
 */
static size_t decode_reserved(uint8_t      *dst_buffer,
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

    RET(len_left < 2, 0, "Not enough space for option");

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

/* this function provides an arbitrary implementation of a IANA assigned
 * experimental option and conforming to RFC 6994 for assuring shared use of
 * the codepoint
 *      kind=254 (0xfe), ExID=57005 (0xdead)
 *
 * structure:
 *      [0]   = 254
 *      [1]   = length of option (between 4 and 8)
 *      [2-3] = 0xdead in network-standard order
 *      [4-]  = incremental-valued bytes starting with 0
 *
 * fills the space with consecutively-valued bytes until the next 32b boundary
 * if start of content is already 32b aligned, 4 more bytes are added
 */
static size_t decode_experimental(uint8_t      *dst_buffer,
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

    RET(len_left < 4, 0, "Not enough space for option");

    /* calculate option offset within option section *
     * if no more space, [4-] can be skipped         */
    option_off = (uint8_t) ((uint64_t) dst_buffer - (uint64_t) ops_sec);
    option_len = 8 - option_off % 4;

    if (len_left < option_len)
        option_len = len_left;

    /* postponing processing */
    if (!dst_buffer) {
        (*usr_ops)++;
        return option_len;
    }

    /* generate option content */
    *dst_buffer++ = ((*usr_ops)++)[0];
    *dst_buffer++ = option_len;
    *(uint16_t *) dst_buffer = htons(0xdead);
    dst_buffer += 2;
    for (uint8_t i=0; i<option_len-4; ++i)
        dst_buffer[i] = i;

    return option_len;
}

/* decode_dummy - dummy decoder for unimplemented options
 *  @return : 0
 *
 * Asking for an unimplemented option will cause this to return 0 (error) and
 * abort the option section generation. Packet will pass unmodified.
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
size_t (*tcp_decoders[0xff])(uint8_t *, size_t, uint8_t **,
                             struct iphdr *, uint8_t *) = {
    [0x00 ... 0xfe] = decode_dummy,

    [0x00] = decode_eool,           /* End Of Options List */
    [0x01] = decode_nop,            /* No OPtion           */
    [0x06] = decode_echo_reply,     /* Echo                */
    [0x07] = decode_echo_reply,     /* Echo Reply          */
    [0x08] = decode_ts,             /* Timestamp           */
    [0x47] = decode_reserved,       /* Reserved Option     */
    [0xfe] = decode_experimental,   /* Experimental Option */
};

/* option processing priority                         *
 *  NOTE: smaller value means higher priority         *
 *  NOTE: a value of 0 means immediate processing     *
 *  NOTE: multiple options can have the same priority */
uint64_t tcp_ops_prio[0xff] = {
    [0x00 ... 0xfe] = 0,

    [0x00] = 0,                     /* End Of Options List */
    [0x01] = 0,                     /* No OPtion           */
    [0x06] = 0,                     /* Echo                */
    [0x07] = 0,                     /* Echo Reply          */
    [0x08] = 0,                     /* Timestamp           */
    [0x47] = 0,                     /* Reserved Option     */
    [0xfe] = 0,                     /* Experimental Option */
};

