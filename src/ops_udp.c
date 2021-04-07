#include <sys/time.h>       /* gettimeofday    */
#include <arpa/inet.h>      /* htonl           */

#include "util.h"           /* DIE, ABORT, RET */
#include "ops_udp.h"

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

static size_t decode_ts(uint8_t         *dst_buffer,
                        size_t          len_left,
                        uint8_t         **usr_ops,
                        struct iphdr    *iph,
                        uint8_t         *ops_sec)
{
    struct timeval  tv;
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
     *       non-decreasing in time                                     */
    ans = gettimeofday(&tv, NULL);
    RET(ans == -1, 0, "Unable to get time of day (%d)", errno);

    /* unlike tcp timestamp, we don't care about TSecr (always 0) */
    dst_buffer[0] = ((*usr_ops)++)[0];  /* kind   */
    dst_buffer[1] = 10;                 /* length */
    *(uint32_t *)(dst_buffer + 2) = htonl((uint32_t) tv.tv_sec);
    *(uint32_t *)(dst_buffer + 6) = 0;

    return 10;
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
size_t (*udp_decoders[0x7f])(uint8_t *, size_t, uint8_t **,
                             struct iphdr *, uint8_t *) = {
    [0x00 ... 0x7e] = decode_dummy,

    [0x00] = decode_eool,   /* End Of Options List */
    [0x01] = decode_nop,    /* No OPeration        */
    [0x07] = decode_ts,     /* TimeStamp           */
};

/* option processing priority                        *
 * NOTE: samller value means higher priority         *
 * NOTE: a value of 0 means immediate processing     *
 * NOTE: multiple options can have the same priority */
uint64_t udp_ops_prio[0x7f] = {
    [0x00 ... 0x7e] = 0,

    [0x00] = 0,             /* End Of Options List */
    [0x01] = 0,             /* No OPtion           */
    [0x07] = 0,             /* TimeStamp           */
};

