#!/bin/bash

# generate_table-1.sh generates line from table 1 in paper
#   arguments: instances.txt directory name (icmp, udp, ...)
#              repeat these 3

# valid receives / valid sends per provider
#
# key format: ${PROVIDER}
declare -A V_RCV
declare -A V_SND

# number of instaces per provider (will hardcode this)
declare -A NUM_INST
NUM_INST[gcloud]=5
NUM_INST[aws]=5
NUM_INST[azure]=5
NUM_INST[docean]=5
NUM_INST[personal]=1

# intialize maps and experiment counter
for it in 'gcloud' 'aws' 'azure' 'docean' 'personal'; do
    V_RCV[${it}]=0
    V_SND[${it}]=0
done

EXPC=0

# main while loop
while [[ $# -ne 0 ]]; do
    # fetch clean instances file, pcap directory and pcap distinctive name
    INSTANCES=${1}
    DIRECTORY=${2}
    NAME=${3}


    printf '\033[32;1m>>>\033[2m processing \033[33m%s\033[32m & \033[33m%s\033[0m\n' \
        "${INSTANCES}" "${DIRECTORY}"

    # consume the three arguments before next round
    shift 3

    # increment experiment counter
    ((EXPC++))

    # for each instance reported
    while read -r DST_PROVIDER DST_REGION DST_IP; do
        # create pcap file name (skip if it doesn't exist
        PCAP_FILE="${DIRECTORY}/${DST_IP}-${NAME}-in.pcap"
        if [[ ! -f ${PCAP_FILE} ]]; then
            continue
        fi
 
        # for each unique IP from which at least a packet was received
        while read SRC_IP; do
            # get src provider
            SRC_PROVIDER=$(grep ${SRC_IP} ${INSTANCES} | awk '{print $1}')

            # update maps
            ((V_RCV[${DST_PROVIDER}]++))
            ((V_SND[${SRC_PROVIDER}]++))
        done < <(tshark -r ${PCAP_FILE} | awk '{print $3}' | sort -u)
    done <${INSTANCES} 2>/dev/null

    # print updated results after round finishes
    TOT=0
    printf '\033[34;1m >>\033[2m round results are:\033[0m\n'
    for it in 'gcloud' 'aws' 'azure' 'docean' 'personal'; do
        printf '\033[36;1m  >\033[2m V_RCV[\033[33m%8s\033[36m]=%4d\033[0m (%6.2f%%)\n' \
            ${it} ${V_RCV[${it}]} \
            $(echo "scale=2; ${V_RCV[${it}]} * 5 / ${EXPC} / ${NUM_INST[${it}]}" | bc)
        ((TOT+=${V_RCV[${it}]}))
    done
    printf '\033[36;1m  >\033[2m total: \033[33m%4d\033[0m\n' ${TOT}
    TOT=0
    for it in 'gcloud' 'aws' 'azure' 'docean' 'personal'; do
        printf '\033[35;1m  >\033[2m V_SND[\033[33m%8s\033[35m]=%4d\033[0m (%6.2f%%)\n' \
            ${it} ${V_SND[${it}]} \
            $(echo "scale=2; ${V_SND[${it}]} * 5 / ${EXPC} / ${NUM_INST[${it}]}" | bc)
        ((TOT+=${V_SND[${it}]}))
    done
    printf '\033[35;1m  >\033[2m total: \033[33m%4d\033[0m\n' ${TOT}
done


