#!/bin/bash

# start_aws_instances.sh - starts aws instances in multiple areas
#   $LOG_FILE : [optional] log file for aws outputs (has default)
#   $OUT_DIR  : [optional] output dir for logs      (has defualt)
#
# make sure that you have configured an "allow all" firewall rule
# aws limits ingress of the "default" security group
#   $ for it in $(aws ec2 describe-regions           \
#                     --query 'Regions[].RegionName' \
#                     --output text); do
#       aws ec2 authorize-security-group-ingress \
#           --region $it                         \
#           --group-name default                 \
#           --cidr 0.0.0.0/0                     \
#           --protocol all                       \
#           --port all                           \
#     done
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

# disable output pager (default is less)
export AWS_PAGER=''

# regions list
#   $ aws ec2 describe-regions --all-regions
REGIONS=(
    us-east-1               `# North Virginia  `
    eu-central-1            `# Frankfurt       `
    ap-south-1              `# Mumbai          `
    me-south-1              `# Manama          `
    sa-east-1               `# Sao Paulo       `
)

# instance type
#   $ aws ec2 describe-instance-types
INSTANCE_TYPE='t3.medium'   # 2 CPUs, 4GB ram

# image type
#   $ awk ec2 describe-images
IMAGE_TYPE='ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64*'

# keypair name
#   $ for it in $(aws ec2 describe-regions          \
#                   --query 'Regions[].RegionName'  \
#                   --output text); do
#       AWS_PAGER=''                                \
#       aws ec2 import-key-pair                     \
#           --key-name KEY_NAME                     \
#           --region ${it}                          \
#           --public-key-material fileb://${HOME}/.ssh/id_rsa.pub
#     done
KEYPAIR_NAME='victim-key'

###############################################################################
################################# ENTRY POINT #################################
###############################################################################

# clean up previous log file (if any)
rm -f ${LOG_FILE}
mkdir -p ${OUT_DIR}

# for each region in which we want to create an instance
for REGION in ${REGIONS[@]}; do
    # zones may become unavailable at any time
    # select a zone from the current region (should be the same every time)
    TELL "retrieving zone from region ${YELLOW}%s${CLR}" ${REGION}
    ZONE=$(aws ec2 describe-availability-zones          \
               --region ${REGION}                       \
               --query 'AvailabilityZones[*].ZoneName'  \
               --output text                            \
           | awk '{print $1}') 2>>${LOG_FILE}
    [[ ${#ZONE} -gt 0 ]]
    DIE $?

    # determine if the current region has our desired instance type available
    TELL "checking availability of ${YELLOW}%s${CLR} in ${YELLOW}%s${CLR}" \
        ${INSTANCE_TYPE} ${REGION}
    aws ec2 describe-instance-types                 \
        --region ${REGION}                          \
        --query 'InstanceTypes[*].[InstanceType]'   \
        --output text                               \
    | grep ${INSTANCE_TYPE} 1>/dev/null 2>>${LOG_FILE}
    DIE $?

    # extract the latest desired image available in current region
    TELL "extracting latest image available in ${YELLOW}%s${CLR}" ${REGION}
    IMAGE=$(aws ec2 describe-images                                           \
              --region ${REGION}                                              \
              --filters                                                       \
                "Name=name,Values=${IMAGE_TYPE}"                              \
                'Name=image-type,Values=machine'                              \
                'Name=block-device-mapping.delete-on-termination,Values=true' \
                'Name=block-device-mapping.encrypted,Values=false'            \
                'Name=is-public,Values=true'                                  \
                'Name=root-device-type,Values=ebs'                            \
                'Name=state,Values=available'                                 \
                'Name=virtualization-type,Values=hvm'                         \
              --query 'Images[*].[ImageId,CreationDate]'                      \
              --output text                                                   \
            | sort -rk 2                                                      \
            | awk 'NR==1 {print $1}') 2>>${LOG_FILE}
    [[ ${#IMAGE} -gt 0 ]]
    DIE $?

    # start the instance
    TELL "starting instance in ${YELLOW}%s${CLR}" ${REGION}
    aws ec2 run-instances                                                  \
        --region ${REGION}                                                 \
        --placement "AvailabilityZone=${ZONE}"                             \
        --count 1                                                          \
        --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=10}' \
        --image-id ${IMAGE}                                                \
        --instance-type ${INSTANCE_TYPE}                                   \
        --key-name ${KEYPAIR_NAME}                                         \
        --monitoring 'Enabled=false'                                       \
        --associate-public-ip-address                                      \
    &>>${LOG_FILE}
    DIE $?
done

# wait for all instances to start (on all regions)
# TODO: this can be integrated in the following step for better performance
TELL "waiting for all instances to boot with active ssh service"; echo
for REGION in ${REGIONS[@]}; do
    for EXT_IP in $(aws ec2 describe-instances                                 \
                        --query 'Reservations[*].Instances[*].PublicIpAddress' \
                        --region ${REGION}                                     \
                        --output text                                          \
                    2>>${LOG_FILE}); do
        TELL "checking ${YELLOW}%s:22${CLR} on ${YELLOW}%s${CLR}" \
            ${EXT_IP} ${REGION}
        while [[ 1 ]]; do
            nc -w 3 ${EXT_IP} 22 &>/dev/null
            if [[ $? -eq 0 ]]; then
                break
            fi
        done
        DIE 0
    done
done

# create USER on each machine for compatibility with gcloud instances
for REGION in ${REGIONS[@]}; do
    for EXT_IP in $(aws ec2 describe-instances                                 \
                        --query 'Reservations[*].Instances[*].PublicIpAddress' \
                        --filter 'Name=instance-state-name,Values=running'     \
                        --region ${REGION}                                     \
                        --output text                                          \
                    2>>${LOG_FILE}); do
        TELL "performing initial setup on ${YELLOW}%s${CLR}" ${EXT_IP}; echo

        SSH ubuntu@${EXT_IP}                                        \
            "sudo adduser --disabled-password --gecos '' ${USER}"   \
            "creating user ${YELLOW}%s${CLR}" ${USER}

        SSH ubuntu@${EXT_IP}                \
            "sudo cp -r .ssh /home/${USER}" \
            "sharing authorized_keys with new user"

        SSH ubuntu@${EXT_IP}                                    \
            "sudo chown -R ${USER}:${USER} /home/${USER}/.ssh"  \
            "setting user ownership of .ssh"

        SSH ubuntu@${EXT_IP}                                                        \
            "sudo bash -c 'echo \"${USER} ALL=(ALL) NOPASSWD:ALL\" >>/etc/sudoers'" \
            "disabling sudo prompt for new user"
    done
done

# save instances list (with IPs) to disk
printf '==========[ AWS INSTANCES ]==========\n' >>${OUT_DIR}/instances.txt
for REGION in ${REGIONS[@]}; do
    TELL "saving ${YELLOW}%s${CLR} instances list to disk" ${REGION}
    FIELDS='Placement.AvailabilityZone,PrivateIpAddress,PublicIpAddress'
    aws ec2 describe-instances                             \
        --query "Reservations[*].Instances[*].[${FIELDS}]" \
        --filter 'Name=instance-state-name,Values=running' \
        --region ${REGION}                                 \
        --output text                                      \
        1>>${OUT_DIR}/instances.txt                        \
        2>>${LOG_FILE}
    DIE $?
done

