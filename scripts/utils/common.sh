#!/bin/bash

# common.sh - utils that require calls to multiple APIs
#   $LOG_FILE  : [optional] log file for all  outputs (has default)
#   $API_VERS  : [optional] gcloud cli api version    (has default)
#   $RES_GROUP : [required] azure resource group
#   $PROJECT   : [required] gcloud project name

###############################################################################
############################## CONFIG VARIABLES ###############################
###############################################################################

# import util functions / variables
# NOTE: make sure there are no conflicts
source $(realpath $(dirname ${BASH_SOURCE[0]}))/../utils/util.sh

# set default values for environment arguments
LOG_FILE=${LOG_FILE:-'api.log'}
API_VERS=${API_VERS:-'beta'}

# disable gcloud interactive mode (defaults will be used on prompt)
CLOUDSDK_CORE_DISABLE_PROMPTS=1

# disable aws output pager (default is less)
export AWS_PAGER=''

# reserved variabes
EXT_IPS=''

PERSONAL_IPS=(
    `# TODO: enter personal IPs here`
)

###############################################################################
################################# ENTRY POINT #################################
###############################################################################

# get_ext_ips - retrieves public IPs of all instances from all providers
#   $EXT_IPS : [return] whitespace separated list of IPs
function get_ext_ips {
    # initialize with user's personal instances
    TELL "retrieving IPs of private cloud instances"
    EXT_IPS="${PERSONAL_IPS[@]}"
    DIE 0

    # scan gcloud instances
    TELL "retrieving IPs of gcloud instances"
    EXT_IPS="${EXT_IPS}                                                       \
             $(gcloud ${API_VERS} compute instances list --project ${PROJECT} \
              2>>${LOG_FILE}                                                  \
              | tail -n +2                                                    \
              | awk '{print $(NF-1)}'                                         \
              | xargs)"
    DIE $?

    # scan aws instances
    for REGION in $(aws ec2 describe-regions           \
                        --query 'Regions[].RegionName' \
                        --output text); do
        TELL "retrieving IPs of ${YELLOW}%s${CLR} aws instances" ${REGION}
        EXT_IPS="${EXT_IPS}                                                   \
                 $(aws ec2 describe-instances                                 \
                       --query 'Reservations[*].Instances[*].PublicIpAddress' \
                       --region ${REGION}                                     \
                       --output text                                          \
                   2>>${LOG_FILE}                                             \
                   | xargs)"
        DIE $?
    done

    # scan azure instances
    TELL "Retrieving IPs of azure instances"
    EXT_IPS="${EXT_IPS}                          \
             $(az vm list                        \
                   --resource-group ${RES_GROUP} \
                   --show-details                \
                   --query '[].publicIps'        \
                   --output tsv                  \
               2>>${LOG_FILE}                    \
               | xargs)"
    DIE $?

    # scan digital ocean instances
    TELL "Retrieving IPs of digital ocean instances"
    EXT_IPS="${EXT_IPS}                   \
             $(doctl compute droplet list \
                    --format PublicIPv4   \
                    --no-header           \
               2>>${LOG_FILE}             \
               | xargs)"
    DIE $?

    # format EXT_IPS for good measure
    EXT_IPS="$(echo ${EXT_IPS} | xargs)"
}

