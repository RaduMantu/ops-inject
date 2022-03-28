#!/bin/bash

# launch_ping_experiment.sh - start icmp echo experiment
#   $LOG_FILE : [optional] log file for gcloud ouputs (has default)
#   $API_VERS : [optional] gcloud cli api version     (has default)
#   $OUT_DIR  : [optional] output dir for logs        (has default)
#   $ADD_DEPS : [optional] if 1 installs dependencies (has default)
#
# must have previously launched up to 6 instances using launch_instance.sh
# NOTE: check util.sh for aditional environment arguments

###############################################################################
############################## CONFIG VARIABLES ###############################
###############################################################################

# import util functions / variables
# NOTE: make sure there are no conflicts
source $(realpath $(dirname ${BASH_SOURCE[0]}))/../utils/util.sh
source $(realpath $(dirname ${BASH_SOURCE[0]}))/../utils/common.sh

# set default values for environment arguments
LOG_FILE=${LOG_FILE:-'api.log'}
API_VERS=${API_VERS:-'beta'}
OUT_DIR=${OUT_DIR:-'logs'}
ADD_DEPS=${ADD_DEPS:-1}

OUT_DIR=${OUT_DIR%/}

###############################################################################
################################# ENTRY POINT #################################
###############################################################################

# clean up & prep
rm -f ${LOG_FILE}
mkdir -p ${OUT_DIR}

# get external IPs of started instances
get_ext_ips

# install dependencies
if [[ ${ADD_DEPS} -eq 1 ]]; then
    for EXT_IP in ${EXT_IPS}; do
        SSH ${EXT_IP}                               \
            "sudo apt update && sudo apt install -y \
             tcpdump iputils-ping"                  \
            "installing dependencies on ${YELLOW}%s${CLR}" ${EXT_IP}
    done
fi

# clean up files from any previous run
for EXT_IP in ${EXT_IPS}; do
    # stop any currently running tcpdump instances
    # NOTE: script might have crashed before terminating them
    SSH ${EXT_IP}                        \
        "sudo kill -9 \$(pidof tcpdump)" \
        "terminating rogue processes on ${YELLOW}%s${CLR}" ${EXT_IP}

    # delete any non-hidden file / directory in remote $HOME
    # NOTE: some files might be write protected
    SSH ${EXT_IP}          \
        "sudo rm -f *pcap" \
        "cleaning up HOME"
done

# start tcpdump instances
for EXT_IP in ${EXT_IPS}; do
    # inbound / outbound for icmp
    SSH ${EXT_IP}                                                             \
        "nohup sudo tcpdump -i any -Uw ${EXT_IP}-icmp-in.pcap                 \
         src $(echo ${EXT_IPS/${EXT_IP}} | xargs | sed 's/ / or /g') and icmp \
         &>/dev/null &                                                        \
         ${BG_PROCESS_CHECK}"                                                 \
        "starting ${YELLOW}inbound icmp${CLR} capture on ${YELLOW}%s${CLR}"   \
        ${EXT_IP}
    SSH ${EXT_IP}                                                             \
        "nohup sudo tcpdump -i any -Uw ${EXT_IP}-icmp-out.pcap                \
         dst $(echo ${EXT_IPS/${EXT_IP}} | xargs | sed 's/ / or /g') and icmp \
         &>/dev/null &                                                        \
         ${BG_PROCESS_CHECK}"                                                 \
        "starting ${YELLOW}outbound icmp${CLR} capture on ${YELLOW}%s${CLR}"  \
        ${EXT_IP}
done

# run experiment
for EXT_IP in ${EXT_IPS}; do
    # for each of the other instances
    for OTHER_EXT_IP in ${EXT_IPS/${EXT_IP}}; do
        # send 3 pings with the hex enconding of each byte of the private and
        # public IP addresses as pattern (will be repeated to 16 bytes)
        #
        # NOTE: timeout is larger in order to receive all responses, so that
        #       ping won't fasely report an error to the calling script
        SSH ${OTHER_EXT_IP}                                                \
            "ping ${EXT_IP} -c 3 -w 10 -p                                  \
                  \$(IFS=. read -r B1 B2 B3 B4 B5 B6 B7 B8                 \
                     <<<\"${OTHER_EXT_IP}.\$(dig +short myip.opendns.com   \
                                                 @resolver1.opendns.com)\" \
                     && printf \"%02x%02x%02x%02x%02x%02x%02x%02x\"        \
                        \${B1} \${B2} \${B3} \${B4}                        \
                        \${B5} \${B6} \${B7} \${B8})"                      \
            "testing ${YELLOW}%s${CLR} ==> ${YELLOW}%s${CLR} (w/ ext IP)"  \
            ${OTHER_EXT_IP} ${EXT_IP}
    done
done

# stop tcpdump processes and copy logs
for EXT_IP in ${EXT_IPS}; do
    SSH ${EXT_IP}                        \
        "sudo kill -9 \$(pidof tcpdump)" \
        "stopping tcpdump on ${YELLOW}%s${CLR}" ${EXT_IP}

    SCP ${EXT_IP}:~/\*pcap ${OUT_DIR} \
        "copying captures on localhost"
done

