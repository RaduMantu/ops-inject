#!/bin/bash

# anayze_icmp-rr.sh - extract ip record route reachability and path
#   $1 : clean instances.txt
#   $2 : directory containing pcaps

###############################################################################
################################# ENTRY POINT #################################
###############################################################################

# argument check
if [[ $# -ne 2 || ! -f $1 || ! -d $2 ]]; then
    echo 'Usage: ./analyze_icmp.sh clean-instances.txt pcap_dir/'
    exit 1
fi

# for each instance reported
while read -r PROVIDER REGION EXT_IP; do
    printf "\033[32;1m>>>> dst:\033[2m %-8s %-20s\033[0m (%s)\n" \
        ${PROVIDER} ${REGION} ${EXT_IP}

    # create appropriate pcap file
    # NOTE: only interested in input
    PCAP_FILE="${2}/${EXT_IP}-icmp-in.pcap"

    # for each first echo request from unique IP
    while read -r PKT_ID SRC_IP; do
        # get provider and region associated with src ip
        read -r SRC_PROVIDER SRC_REGION < <(grep ${SRC_IP} ${1} \
                                            | awk '{print $1" "$2}')

        printf "\033[34;1m >>> src:\033[2m %-8s %-20s\033[0m (%s)\n" \
            ${SRC_PROVIDER} ${SRC_REGION} ${SRC_IP}

        # fetch original TTL
        ORG_TTL=$(tshark -r ${2}/${SRC_IP}-icmp-out.pcap         \
                         -Y "ip.addr==${EXT_IP} && icmp.type==8" \
                         -e ip.ttl                               \
                         -T ek                                   \
                  | grep 'ip_ttl'                                \
                  | head -n 1                                    \
                  | jq -Ma '.layers.ip_ttl'                      \
                  | tr -d '"[]'                                  \
                  | xargs)

        # fetch final TTL
        FIN_TTL=$(tshark -r ${PCAP_FILE}              \
                         -Y "frame.number==${PKT_ID}" \
                         -e ip.ttl                    \
                         -T ek                        \
                  | tail -n 1                         \
                  | jq -Ma '.layers.ip_ttl'           \
                  | tr -d '"[]'                       \
                  | xargs)
        printf "\033[33;1m  >> ttl:\033[2m %d\033[0m\n" \
            $((${ORG_TTL} - ${FIN_TTL}))

        # for each ip in timestamp option
        for TS_IP in $(tshark -r ${PCAP_FILE}              \
                              -Y "frame.number==${PKT_ID}" \
                              -e ip.rec_rt                 \
                              -T ek                        \
                       | tail -n 1                         \
                       | jq -Ma '.layers.ip_rec_rt'        \
                       | tr -d '",[]'                      \
                       | xargs); do
            printf "\033[33;1m  >> hop:\033[2m %s\033[0m\n" ${TS_IP}

            # get organization info
            # NOTE: whois can access either RIPE or ARIN databases
            #       account for different formats
            NET_NAME="$(whois ${TS_IP}            \
                        | grep -e 'NetName'       \
                               -e 'netname'       \
                        | tail -n 1               \
                        | awk '{$1=""; print $0}' \
                        | xargs)"
            ORG_NAME="$(whois ${TS_IP}            \
                        | grep -e 'OrgName'       \
                               -e 'mnt-by'        \
                        | tail -n 1               \
                        | awk '{$1=""; print $0}' \
                        | xargs)"
            printf "\033[31;1m   > NetName:\033[2m %s\033[0m\n" \
                "${NET_NAME:-N/A}"
            printf "\033[31;1m   > OrgName:\033[2m %s\033[0m\n" \
                "${ORG_NAME:-N/A}"

            # get autonomous system number and name
            AS_NUM="$(whois -h whois.cymru.com -- -v ${TS_IP} \
                      | tail -n 1                             \
                      | cut -d'|' -f1                         \
                      | xargs)"
            AS_COUNTRY="$(whois -h whois.cymru.com -- -v ${TS_IP} \
                          | tail -n 1                             \
                          | cut -d'|' -f4                         \
                          | xargs)"
            AS_NAME="$(whois -h whois.cymru.com -- -v ${TS_IP} \
                       | tail -n 1                             \
                       | cut -d'|' -f7                         \
                       | xargs)"
            printf "\033[31;1m   > AS Num :\033[2m %s\033[0m\n" \
                "${AS_NUM:-N/A}"
            printf "\033[31;1m   > AS Name:\033[2m %s\033[0m\n" \
                "${AS_NAME:-N/A}"
            printf "\033[31;1m   > Country:\033[2m %s\033[0m\n" \
                "${AS_COUNTRY:-N/A}"
        done
    done < <(tshark -r ${PCAP_FILE} -Y 'icmp.type==8' \
             | awk '{print $1" "$3}'                  \
             | sort -uk2)
done <${1}

