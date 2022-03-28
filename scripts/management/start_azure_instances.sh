#!/bin/bash

# start_azure_instances.sh - stats azure instances in multiple areas
#   $LOG_FILE : [optional] log file for azure outputs (has default)
#   $OUT_DIR  : [optional] output dir for logs        (has default)
#
# NOTE: check util.sh for additional environment arguments

###############################################################################
############################## CONFIG VARIABLES ###############################
###############################################################################

# import util function / variables
# NOTE: make sure there are no conflicts
source $(realpath $(dirname ${BASH_SOURCE[0]}))/../utils/util.sh

# set default values for environment arguments
LOG_FILE=${LOG_FILE:-'api.log'}
OUT_DIR=${OUT_DIR:-'logs'}
RES_GROUP=${RES_GROUP:-'default-grp'}

# regions list
#   $ az account list-locations                           \
#       --query "[].{DisplayName:displayName, Name:name}" \
#       -o table
REGIONS=(
    canadacentral               `# Canada               `
    centralus                   `# Central United States`
    koreacentral                `# South Korea          `
    francecentral               `# France               `
    australiacentral            `# Australia            `
)

# instance size
#   $ az vm list-sizes -l ${REGION} -o table
INSTANCE_SIZE='Standard_B1s'

# image name
#   $ az vm image list -f Ubuntu -o table
IMAGE_NAME='UbuntuLTS'

# public key file
PUB_KEY="${HOME}/.ssh/id_rsa.pub"

###############################################################################
################################# ENTRY POINT #################################
###############################################################################

# clean up previous log file (if any)
rm -f ${LOG_FILE}
mkdir -p ${OUT_DIR}

# for each region in which we want to create an instance
for REGION in ${REGIONS[@]}; do
    # create instance
    TELL "Starting instance in ${YELLOW}%s${CLR}" ${REGION}
    az vm create \
        --name                         "${REGION}-instance" \
        --resource-group               ${RES_GROUP}         \
        --image                        ${IMAGE_NAME}        \
        --location                     ${REGION}            \
        --size                         ${INSTANCE_SIZE}     \
        --admin-username               ${USER}              \
        --ssh-key-values               ${PUB_KEY}           \
        --authentication-type          ssh                  \
        --public-ip-address            "${REGION}-pubIp"    \
        --public-ip-address-allocation static               \
    &>>${LOG_FILE}
    DIE $? 

    # open all ports on instance
    TELL "Opening all ports"
    az vm open-port                           \
        --port           '*'                  \
        --resource-group ${RES_GROUP}         \
        --name           "${REGION}-instance" \
    &>>${LOG_FILE}
    DIE $?
done

# save instances list (with IPs) to disk
TELL "saving instances list to disk"
printf '==========[ AZURE INSTANCES ]==========\n' >>${OUT_DIR}/instances.txt
az vm list                        \
    --resource-group ${RES_GROUP} \
    --show-details                \
    -o table                      \
1>>${OUT_DIR}/instances.txt       \
2>>${LOG_FILE}
DIE $?

