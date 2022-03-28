#!/bin/bash

# start_docean_instances.sh- starts digital ocean instances in multiple areas
#   $SSH_KEY_ID : [required] ssh key id (see description below)
#   $LOG_FILE   : [optional] log file for doctl output (has default)
#   $OUT_DIR    : [optional] output dir for logs       (has defualt)
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
OUT_DIR=${OUT_DIR:-'logs'}

# region list
#   $ doctl compute region list
REGIONS=(
    nyc1                    `# New York`
    fra1                    `# Frankfurt`
    sgp1                    `# Singapore`
    tor1                    `# Toronto`
    blr1                    `# Bangalore`
)

# instance type
#   $ doctl compute size list
INSTANCE_TYPE='s-1vcpu-2gb'

# image
#   $ doctl compute image list --public
IMAGE='ubuntu-18-04-x64'

# ssh key id (you can set default value here)
#   $ doctl compute ssh-key list
SSH_KEY_ID=${SSH_KEY_ID:-'00000000'}

###############################################################################
################################# ENTRY POINT #################################
###############################################################################

# clean up previous log file (if any)
rm -f ${LOG_FILE}
mkdir -p ${OUT_DIR}

# for each region in which we want to create an instance
for REGION in ${REGIONS[@]}; do
    # compose instance name
    INST_NAME="inst-${REGION}"

    # start instance
    TELL "starting instance ${YELLOW}%s${CLR}" ${INST_NAME}
    doctl compute droplet create ${INST_NAME} \
        --image ${IMAGE}                      \
        --region ${REGION}                    \
        --size ${INSTANCE_TYPE}               \
        --ssh-keys ${SSH_KEY_ID}              \
        --wait                                \
        &>>${LOG_FILE}
    DIE $?

    # default user is root; we want to add $USER as well
    TELL "getting public IP of ${YELLOW}%s${CLR} instance" ${INST_NAME}
    EXT_IP=$(doctl compute droplet list --format Name,PublicIPv4 \
             | grep ${INST_NAME}                                 \
             | awk '{print $2}'                                  \
             2>>${LOG_FILE})
    DIE $?

    TELL "waiting for ssh server on ${YELLOW}%s:22${CLR}" ${EXT_IP}
    while [[ 1 ]]; do
        SSHV -o ConnectTimeout=1 -o ConnectionAttempts=1 \
             root@${EXT_IP}                              \
             'exit'                                      \
             &>/dev/null
        if [[ $? -eq 0 ]]; then
            break
        fi
    done
    DIE 0

    SSH root@${EXT_IP}                                        \
        "sudo adduser --disabled-password --gecos '' ${USER}" \
        "creating user ${YELLOW}%s${CLR}" ${USER}

    SSH root@${EXT_IP}                  \
        "sudo cp -r .ssh /home/${USER}" \
        "sharing authorized_keys with new user"

    SSH root@${EXT_IP}                                     \
        "sudo chown -R ${USER}:${USER} /home/${USER}/.ssh" \
        "setting user ownership of .ssh"

    SSH root@${EXT_IP}                                           \
        "echo \"${USER} ALL=(ALL) NOPASSWD:ALL\" >>/etc/sudoers" \
        "disabling sudo prompt for new user"
done


# save instances list (with IPs) to disk
TELL "saving instances list to disk"
printf '==========[ DOCEAN INSTANCES ]==========\n' >>${OUT_DIR}/instances.txt
doctl compute droplet list      \
    1>>${OUT_DIR}/instances.txt \
    2>>${LOG_FILE}
DIE $?

