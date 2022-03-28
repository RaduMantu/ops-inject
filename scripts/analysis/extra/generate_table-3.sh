#!/bin/bash

# generate_table.sh - generate info for latex udp table in paper
#   I will lose my mind if I have to do this manually
#
# input:
#   sequence of (instances.txt, experiment directory path, name)



# table will show % of annotated udp packets that passed from X to Y
# associative map will hold total number of working experiments
# key for associative map is as follows:
#   "${SRC_PROVIDER}_${SRC_REGION}:${DST_PROVIDER}_${DST_REGION}"
declare -A VEXP
declare -A BAD

# partial keys in table order
PART_KEYS=(
    'gcloud_us-east1'
    'gcloud_europe-west2'
    'gcloud_asia-southeast1'
    'gcloud_asia-northeast1'
    'gcloud_australia-southeast1'

    'aws_us-east-1'
    'aws_eu-central-1'
    'aws_ap-south-1'
    'aws_me-south-1'
    'aws_sa-east-1'

    'azure_canadacentral'
    'azure_centralus'
    'azure_koreacentral'
    'azure_francecentral'
    'azure_australiacentral'

    'docean_nyc1'
    'docean_fra1'
    'docean_sgp1'
    'docean_tor1'
    'docean_blr1'

    'personal_bucharest'
)

# initialize associative arrays based on partial keys
for K1 in ${PART_KEYS[@]}; do
    for K2 in ${PART_KEYS[@]}; do
        VEXP[${K1}:${K2}]=0
        BAD[${K1}:${K2}]=0
    done
done

# determine number of option tests (max value for each route at the end)
NTESTS=$(($# / 3))

# main while loop
while [[ $# -ne 0 ]]; do
    # fetch clean instances file, associated pcap directory, distinctive name
    INSTANCES=${1}
    DIRECTORY=${2}
    NAME=${3}

    # consume arguments before next round
    shift 3

    printf '\033[34;1m<<<\033[2m testing \033[33m%s\033[0m\n' ${DIRECTORY}

    # for each instance reported
    while read -r DST_PROVIDER DST_REGION DST_IP; do
        # create appropriate pcap file
        # NOTE: only interested in input
        PCAP_FILE="${DIRECTORY}/${DST_IP}-${NAME}-in.pcap"

        printf '\033[34;1m <<\033[2m analysing \033[33m%s\033[0m\n' \
            $(basename ${PCAP_FILE})

        # for each packet with udp ops (one per unique IP)
        while read -r PKT_ID SRC_IP; do
            # get provider and region associated with src IP
            read -r SRC_PROVIDER SRC_REGION < <(grep ${SRC_IP} ${INSTANCES} \
                                                | awk '{print $1, $2}')

            # update valid route count
            ((VEXP[${SRC_PROVIDER}_${SRC_REGION}:${DST_PROVIDER}_${DST_REGION}]++))

        # since this tshark version does not know udp option, make sure that
        # ip.tot_len - udp.len - ip.header_len > 0
        done < <(tshark -r ${PCAP_FILE}                                   \
                        -Y 'ip.proto == 17'                               \
                        -e frame.number -e ip.src -e ip.len -e udp.length \
                        -T fields                                         \
                 | awk '{ if ($3 - $4 - 20 >= 0) { print $1, $2 } }'       \
                 | sort -uk2)

        continue

        # for each packet with udp ops (one per unique IP)
        while read -r PKT_ID SRC_IP; do
            # get provider and region associated with src IP
            read -r SRC_PROVIDER SRC_REGION < <(grep ${SRC_IP} ${INSTANCES} \
                                                | awk '{print $1, $2}')

            # update valid route count
            ((BAD[${SRC_PROVIDER}_${SRC_REGION}:${DST_PROVIDER}_${DST_REGION}]++))

        # since this tshark version does not know udp option, make sure that
        # ip.tot_len - udp.len - ip.header_len > 0
        done < <(tshark -r ${PCAP_FILE}                                   \
                        -Y 'ip.proto == 17'                               \
                        -e frame.number -e ip.src -e ip.len -e udp.length \
                        -T fields                                         \
                 | awk '{ if ($3 - $4 - 20 == 0) { print $1, $2 } }'       \
                 | sort -uk2)
    done <${INSTANCES}
done

# print result in table order
for K1 in ${PART_KEYS[@]}; do
    printf '\033[32;1m>>>\033[2m %s\033[0m\n' ${K1}

    for K2 in ${PART_KEYS[@]}; do
        printf ' & '

#        if [[ BAD[${K1}:${K2}] -ne 0 ]]; then
#            printf '\\cellcolor{gray!20} '
#        fi

        printf '%.2f' $(echo "scale=2; ${VEXP[${K1}:${K2}]} / ${NTESTS} * 100" | bc) 
    done
    echo
done

