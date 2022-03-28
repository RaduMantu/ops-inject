#!/bin/bash

# launch_quic_experiment.sh - starts quic experiment
#   $1 : [required] zip containing quic client & dependent libraries
#   $2 : [required] file with domains / IPs of http/3 (quic) servers
#
#   $LOG_FILE : [optional] log file for gcloud outputs (has default)
#   $API_VERS : [optional] gcloud cli api version      (has default)
#   $OUT_DIR  : [optional] output dir for logs         (has default)
#   $ADD_DEPS : [optional] if 1 installs dependecies   (has default)
#
# due to some problems with setting up the chromium quic server, we test
# publicly available servers in stead (similar to curl experiment)
#
# must have previouslt launched gcloud instances with launch_instance.sh
# NOTE: check util.sh for additional environment arguments

###############################################################################
############################## CONFIG VARIABLES ###############################
###############################################################################

# import util functions / variables
# NOTE: make sure there are no conflicts
source $(realpath $(dirname ${BASH_SOURCE[0]}))/../utils/util.sh
source $(realpath $(dirname ${BASH_SOURCE[0]}))/../utils/common.sh

# cli argument check
TELL "checking script arguments"
[[ ${#} -eq 2       # two arguments
&& -f ${1}          # archive exists
&& -f ${2} ]]       # domains file exists
DIE $?

# rename cli arguments
ARCHIVE_FILE=${1}
DOMAINS_FILE=${2}

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
             tcpdump unzip"                         \
            "installing dependencies on ${YELLOW}%s${CLR}" ${EXT_IP}
    done
fi

# clean up files from any previous run & load quic client dependencies
for EXT_IP in ${EXT_IPS}; do
    # delete any non-hidden file / directory in remote $HOME
    # NOTE: some files might be write protected
    SSH ${EXT_IP}                                 \
        "sudo rm -rf *pcap *log *zip quic_export" \
        "cleaning up HOME on ${YELLOW}%s${CLR}" ${EXT_IP}

    # move archive with precompiled client & libraries to remote
    # move domains list to remote
    SCP ${ARCHIVE_FILE} ${EXT_IP}:~/ \
        "exporting precompiled binaries archive"
    SCP ${DOMAINS_FILE} ${EXT_IP}:~/ \
        "exporting domains list"

    # decompress remote archive
    SSH ${EXT_IP}                           \
        "unzip $(basename ${ARCHIVE_FILE})" \
        "decompressing remote archive"
done

# start tcpdump instances
for EXT_IP in ${EXT_IPS}; do
    # inbound / outbound for udp ports 80 and 443
    # NOTE: temporarily removing "src/dst port '(80 or 443)'
    SSH ${EXT_IP}                                                            \
        "nohup sudo tcpdump -i any -Uw ${EXT_IP}-quic-in.pcap                \
         src $(echo ${EXT_IPS/${EXT_IP}} | xargs | sed 's/ / or /g') and udp \
         &>/dev/null &                                                       \
        ${BG_PROCESS_CHECK}"                                                 \
        "starting ${YELLOW}inbound quic${CLR} capture on ${YELLOW}%s${CLR}"  \
        ${EXT_IP}
    SSH ${EXT_IP}                                                            \
        "nohup sudo tcpdump -i any -Uw ${EXT_IP}-quic-out.pcap               \
         dst $(echo ${EXT_IPS/${EXT_IP}} | xargs | sed 's/ / or /g') and udp \
         &>/dev/null &                                                       \
        ${BG_PROCESS_CHECK}"                                                 \
        "starting ${YELLOW}outbound quic${CLR} capture on ${YELLOW}%s${CLR}" \
        ${EXT_IP}
done

# run experiment
# NOTE: this can all be parallelized if we add more domains
#       as things stand, it's not worth it losing debug info clarity
for EXT_IP in ${EXT_IPS}; do
    # run quic client on remote server
    # NOTE: some servers may have certificate issues
    #       certificate check can be disabled
    TELL "running quic client experiment on ${YELLOW}%s${CLR}" ${EXT_IP}
    SSHV ${EXT_IP} \
        "while read -r DOMAIN; do
            LD_LIBRARY_PATH=\"\$(realpath quic_export/lib)\" \
            ./quic_export/bin/quic_client \${DOMAIN} &>>client.log

            printf '%-32s -- %3d\\n' \${DOMAIN} \$? &>>quic-${EXT_IP}.log
         done <$(basename ${DOMAINS_FILE})" \
        &>>${LOG_FILE}
    DIE $?
done

# stop tcpdump processes and copy logs
for EXT_IP in ${EXT_IPS}; do
    SSH ${EXT_IP}                        \
        "sudo kill -9 \$(pidof tcpdump)" \
        "stopping tcpdump on ${YELLOW}%s${CLR}" ${EXT_IP}

    SCP ${EXT_IP}:~/\*pcap ${OUT_DIR} \
        "copying captures to localhost"

    SCP ${EXT_IP}:~/quic-\*.log ${OUT_DIR} \
        "copying quic report log"
done

