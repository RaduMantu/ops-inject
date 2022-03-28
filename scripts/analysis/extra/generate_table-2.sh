#!/bin/bash

# generate_table.sh - generate info for latex table in paper
#   I will lose my mind if I have to do this manually
#
# associative arrays holding
#   1) total number of knowledgeable hosts
#   2) number of experiments where the route was valid
#
# key format:
#   "${SRC_PROVIDER}_${SRC_REGION}:${DST_PROVIDER}_${DST_REGION}"
declare -A KH
declare -A VE

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
        # create composite key of entry
        KEY="${K1}:${K2}"

        KH[${KEY}]=0
        VE[${KEY}]=0
    done
done

# start processing logs
while [[ $# -ne 0 ]]; do
    # fetch clean instances file and associated pcap directory
    INSTANCES=${1}
    DIRECTORY=${2}

    # consume the two arguments before next round
    shift 2

    # for each instance reported
    while read -r DST_PROVIDER DST_REGION DST_IP; do
        # create appropriate pcap file
        # NOTE: only interested in input
        PCAP_FILE="${DIRECTORY}/${DST_IP}-icmp-in.pcap"

        # for each first echo request from unique IP
        while read -r PKT_ID SRC_IP; do
            # get provider and regon associated with src IP
            read -r SRC_PROVIDER SRC_REGION < <(grep ${SRC_IP} ${INSTANCES} \
                                                | awk '{print $1, $2}')

            # get number of knowledgeable hosts
            # NOTE: cheating a bit, but there can't be less than 4 hosts...
            NUM_HOSTS=$(tshark -r ${PCAP_FILE}                \
                               -Y "frame.number==${PKT_ID}"   \
                               -e ip.opt.overflow             \
                               -T ek                          \
                        | tail -n 1                           \
                        | jq -Ma '.layers.ip_opt_overflow[0]' \
                        | tr -d '"')
            NUM_HOSTS=$((NUM_HOSTS + 4))

            # create composite key of entry
            KEY="${SRC_PROVIDER}_${SRC_REGION}:${DST_PROVIDER}_${DST_REGION}"

            # update cumulative number of hops and valid experiments
            KH[${KEY}]=$((KH[${KEY}] + NUM_HOSTS))
            VE[${KEY}]=$((VE[${KEY}] + 1))

            echo ${KEY}         1>&2
            echo ${KH[${KEY}]}  1>&2
            echo ${VE[${KEY}]}  1>&2
            echo "============" 1>&2
        done < <(tshark -r ${PCAP_FILE} -Y 'icmp.type==8' \
                 | awk '{print $1, $3}'                   \
                 | sort -uk2)
    done <${INSTANCES}
done

# print result, in table order
for K1 in ${PART_KEYS[@]}; do
    echo ${K1}

    for K2 in ${PART_KEYS[@]}; do
        # create composite key of entry
        KEY="${K1}:${K2}"

        # print separator
        printf '& '

        # make cell coloured if all experiments passed
        # NOTE: a bit of hardcoding here; don't care
        if [[ ${VE[${KEY}]} -eq 3 ]]; then
            printf '\cellcolor{blue!25} '
        fi

        # print average if any experiment worked; else blank
        if [[ ${VE[${KEY}]} -ne 0 ]]; then

            # bash can't do float calculations
            # NOTE: round it to nearest unit (not enough space in table)
            printf '%.0f ' \
                $(echo "scale=2; ${KH[${KEY}]} / ${VE[${KEY}]}" | bc)
        fi
    done

    echo "\\\\"

    # let's also print number of experiments that worked
    for K2 in ${PART_KEYS[@]}; do
        # create composite key of entry
        KEY="${K1}:${K2}"

        # skip if nothing to show
        if [[ ${VE[${KEY}]} -eq 0 ]]; then
            continue
        fi

        printf '  %20s -- %2d\n' ${K2} ${VE[${KEY}]}
    done
done

