#!/bin/bash

# anayze_reachability.sh - show every instance that managed to reach somewhere
#   $1 : clean instances.txt
#   $2 : directory containing pcaps
#
#   $NAME : tcp, icmp, ... or * if nothing provided
#   $FILT : wireshark display filter for tested option
#           will default to 'ip' which should catch all
#           look at these links for valid filters (ip and tcp):
#               https://www.wireshark.org/docs/dfref/i/ip.html
#               https://www.wireshark.org/docs/dfref/t/tcp.html

###############################################################################
################################# ENTRY POINT #################################
###############################################################################

# set default value
NAME=${NAME:-*}
FILT=${FILT:-ip}

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
    PCAP_FILE="${2}/${EXT_IP}-${NAME}-in.pcap"

    # counter
    COUNT=0

    # for each first echo request from unique IP
    while read -r PKT_ID SRC_IP; do
        # get provider and region associated with src ip
        read -r SRC_PROVIDER SRC_REGION < <(grep ${SRC_IP} ${1} \
                                            | awk '{print $1" "$2}')

        # increment counter
        ((COUNT++))

        printf "\033[34;1m >>> src:\033[2m %-8s %-20s\033[0m (%s)\n" \
            ${SRC_PROVIDER} ${SRC_REGION} ${SRC_IP}
    done < <(tshark -r ${PCAP_FILE}  \
                    -Y ${FILT}       \
               2>/dev/null           \
             | awk '{print $1" "$3}' \
             | sort -uk2)

    printf "\033[33;1m >>> tot:\033[2m %-3d\033[0m\n" ${COUNT}
done <${1}

