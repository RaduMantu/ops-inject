#!/bin/bash

# start_gcloud_instances.sh - starts gcloud instances in multiple areas
#   $GCLOUD_USER : [required] gcloud user name
#   $PROJECT     : [required] gcloud project name
#   $LOG_FILE    : [optional] log file for gcloud outputs (has default)
#   $API_VERS    : [optional] gcloud cli api version      (has default)
#   $PROJECT     : [optional] gcloud project name
#   $OUT_DIR     : [optional] output dir for logs         (has default)
#
# make sure that you have configured a public ssh key for your account
#   $ gcloud beta compute os-login ssh-keys add --key-file id_rsa.pub --ttl 0
#
# make sure that you have configured an "allow all" firewall rule
#   $ gcloud beta compute firewall-rules create default-allow-all \
#         --allow tcp,udp,icmp,esp,ah,sctp                        \
#         --network 'default'                                     \
#         --priority '1000'
#
# NOTE: check util.sh for additional environment arguments

###############################################################################
############################## CONFIG VARIABLES ###############################
###############################################################################

# import util functions / variables
# NOTE: make sure there are no conflicts
source $(realpath $(dirname ${BASH_SOURCE[0]}))/../utils/util.sh

# set default values for environment arguments
LOG_FILE=${LOG_FILE:-'api.log'}
API_VERS=${API_VERS:-'beta'}
OUT_DIR=${OUT_DIR:-'logs'}

# google cloud user name (you can set default value here
# for individual users, this will be something like: your_mail_gmail_com
GCLOUD_USER=${GCLOUD_USER:-'your_mail_gmail_com'}

# disable interactive mode (defaults will be used on prompt)
CLOUDSDK_CORE_DISABLE_PROMPTS=1

# regions list
#   $ gcloud compute zones list
REGIONS=(
    us-east1                `# South Carolina`
    europe-west2            `# London        `
    asia-southeast1         `# Singapore     `
    asia-northeast1         `# Tokyo         `
    australia-southeast1    `# Sydney        `
)

# machine type
#   $ gcloud compute machine-types list
MACHINE_TYPE='e2-medium'    # 2 CPUs, 4GB ram

# image family and project
#   $ gcloud compute images list
IMAGE_FAMILY='ubuntu-minimal-1804-lts'
IMAGE_PROJECT='ubuntu-os-cloud'

# disk size and type
#   $ gcloud compute disk-types list
DISK_SIZE='10GB'
DISK_TYPE='pd-standard'

###############################################################################
################################# ENTRY POINT #################################
###############################################################################

# clean up previous log file (if any)
rm -f ${LOG_FILE}
mkdir -p ${OUT_DIR}

# for each region in which we want to create an instance
for REGION in ${REGIONS[@]}; do
    # zones may become unavailable at any time
    # select a zone from the current region that has our machine type
    #
    # NOTE: disk type may also be a factor but chances are very small
    # NOTE: on trial account, there is a 12cpu limit
    TELL "retrieving zone from region ${YELLOW}%s${CLR}" ${REGION}
    ZONE=$(comm -12                                         \
            <(gcloud ${API_VERS} compute zones list         \
              | grep ${REGION}                              \
              | awk '{print $1}'                            \
              | sort 2>>${LOG_FILE})                        \
            <(gcloud ${API_VERS} compute machine-types list \
              | grep ${MACHINE_TYPE}                        \
              | grep ${REGION}                              \
              | awk '{print $2}'                            \
              | sort 2>>${LOG_FILE})                        \
           | head -n 1                                      \
           | grep ${REGION}) 2>>${LOG_FILE}
    DIE $?

    # compose instance name
    INST_NAME="inst-${REGION}"

    # start instance if not already running
    TELL "starting instace ${YELLOW}%s${CLR}" ${INST_NAME}
    gcloud ${API_VERS} compute instances list 2>${LOG_FILE} \
    | grep ${INST_NAME} 1>/dev/null
    if [ $? -eq 0 ]; then
        WAR 1
        continue
    else
        gcloud ${API_VERS} compute instances create ${INST_NAME}    \
            --project            ${PROJECT}                         \
            --image-family       ${IMAGE_FAMILY}                    \
            --image-project      ${IMAGE_PROJECT}                   \
            --machine-type       ${MACHINE_TYPE}                    \
            --boot-disk-size     ${DISK_SIZE}                       \
            --boot-disk-type     ${DISK_TYPE}                       \
            --zone               ${ZONE}                            \
            --maintenance-policy MIGRATE                            \
            --metadata           enable-oslogin=TRUE                \
            &>>${LOG_FILE}
        DIE $?
    fi

    # gcloud is retarded; if you are not part of an organization, then the
    # username used when setting up your ssh identity defaults to your
    # email; this fucked everything up when I switched to a normal account...
    TELL "getting public IP of ${YELLOW}%s${CLR} instance" ${INST_NAME}
    EXT_IP=$(gcloud compute instances list \
             | grep ${INST_NAME}           \
             | awk '{print $(NF-1)}'       \
             2>>${LOG_FILE})
    DIE $?

    TELL "waiting for ssh server on ${YELLOW}%s:22${CLR}" ${EXT_IP}
    while [[ 1 ]]; do
        SSHV -o ConnectTimeout=1 -o ConnectionAttempts=1 \
             ${GCLOUD_USER}@${EXT_IP}                    \
             'exit'                                      \
             &>/dev/null
        if [[ $? -eq 0 ]]; then
            break
        fi
    done
    DIE 0

    SSH ${GCLOUD_USER}@${EXT_IP}                              \
        "sudo adduser --disabled-password --gecos '' ${USER}" \
        "creating user ${YELLOW}%s${CLR}" ${USER}

    SSH ${GCLOUD_USER}@${EXT_IP}  \
        "sudo runuser             \
            -l ${USER}            \
            -c \"mkdir -p .ssh\"" \
        "creating .ssh for new user"

    SSH ${GCLOUD_USER}@${EXT_IP}                                          \
        "sudo runuser                                                     \
            -l ${USER}                                                    \
            -c \"echo $(cat ~/.ssh/id_rsa.pub) >> .ssh/authorized_keys\"" \
        "initializing authorized_keys"

    SSH ${GCLOUD_USER}@${EXT_IP}                                     \
        "sudo runuser                                                \
            -l ${USER}                                               \
            -c \"chmod 700 .ssh && chmod 400 .ssh/authorized_keys\"" \
        "setting correct permission on .ssh keystore"

    SSH ${GCLOUD_USER}@${EXT_IP}                                                \
        "sudo bash -c 'echo \"${USER} ALL=(ALL) NOPASSWD:ALL\" >>/etc/sudoers'" \
        "disabling sudo prompt for new user"

done


# save instances list (with IPs) to disk
TELL "saving instances list to disk"
printf '==========[ GCLOUD INSTANCES ]==========\n' >>${OUT_DIR}/instances.txt
gcloud ${API_VERS} compute instances list \
    1>>${OUT_DIR}/instances.txt           \
    2>>${LOG_FILE}
DIE $?

