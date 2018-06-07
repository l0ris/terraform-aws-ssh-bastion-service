#cloud-config
---
package_update: true
packages:
  - python-pip

write_files:
  -
    content: |
       FROM ubuntu:16.04

        RUN apt-get update && apt-get install -y openssh-server awscli sudo && echo '\033[1;31mI am a one-time Ubuntu container with passwordless sudo. \033[1;37;41mI will terminate after 12 hours or else on exit\033[0m' > /etc/motd && mkdir /var/run/sshd
        
        COPY installer.sh /opt
        COPY authorized_keys_command.sh /usr/bin/authorized_keys_command.sh
        COPY import_users.sh /usr/bin/import_users.sh
  
        EXPOSE 22
        CMD ["/opt/ssh_startup.sh"]
    path: /opt/sshd_worker/Dockerfile

  -
    content: |
        #!/bin/bash
        # (
        # count=1
        # /opt/iam-authorized-keys-command | while read line
        # do
        #   username=$( echo $line | sed -e 's/^# //' -e 's/+/plus/' -e 's/=/equal/' -e 's/,/comma/' -e 's/@/at/' )
        #   useradd -m -s /bin/bash -k /etc/skel $username
        #   usermod -a -G sudo $username
        #   echo $username\ 'ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/$count
        #   chmod 0440 /etc/sudoers.d/$count
        #   count=$(( $count + 1 ))
        #   mkdir /home/$username/.ssh
        #   read line2
        #   echo $line2 >> /home/$username/.ssh/authorized_keys
        #   chown -R $username:$username /home/$username/.ssh
        #   chmod 700 /home/$username/.ssh
        #   chmod 0600 /home/$username/.ssh/authorized_keys
        # done

        # ) > /dev/null 2>&1

        /usr/bin/import_users.sh

        /usr/sbin/sshd -i
    path: /opt/sshd_worker/ssh_startup.sh
    permissions: '0754'

  -
    content: |
        [Unit]
        Description=SSH Socket for Per-Connection docker ssh container

        [Socket]
        ListenStream=22
        Accept=true

        [Install]
        WantedBy=sockets.target
    path: /etc/systemd/system/sshd_worker.socket

  -
    content: |
        [Unit]
        Description=SSH Per-Connection docker ssh container

        [Service]
        Type=simple
        ExecStart= /usr/bin/docker run --rm -i --hostname ${bastion_host_name}_%i -v /dev/log:/dev/log -v /opt/iam_helper:/opt:ro sshd_worker
        StandardInput=socket
        RuntimeMaxSec=43200

        [Install]
        WantedBy=multi-user.target
    path: /etc/systemd/system/sshd_worker@.service

  -
    content: |
        #!/bin/bash
        #debian specific set up for docker https://docs.docker.com/install/linux/docker-ce/debian/#install-using-the-repository
        sudo apt install -y apt-transport-https ca-certificates curl gnupg2 software-properties-common
        curl -fsSL https://download.docker.com/linux/$(. /etc/os-release; echo "$ID")/gpg | sudo apt-key add -
        sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/$(. /etc/os-release; echo "$ID") $(lsb_release -cs) stable"
        sudo apt update
        sudo apt install -y docker-ce
        sudo  pip install awscli
        #set host sshd to run on port 2222 and restart service
        sed -i 's/#Port[[:blank:]]22/Port\ 2222/'  /etc/ssh/sshd_config
        systemctl restart sshd.service
        systemctl enable sshd_worker.socket
        systemctl start sshd_worker.socket
        systemctl daemon-reload
        #Build sshd service container
        cd /opt/sshd_worker
        systemctl start docker
        docker build -t sshd_worker .
        mkdir /opt/iam_helper
        #set hostname to match dns
        hostname -b ${bastion_host_name}-${vpc}-bastion-host
        echo ${bastion_host_name}-bastion-host > /etc/hostname
        echo '127.0.0.1 ${bastion_host_name}-bastion-host' | sudo tee --append /etc/hosts
    path: /var/lib/cloud/scripts/per-once/localinstall.sh
    permissions: '0754'

  -
    content: |
        IAM_AUTHORIZED_GROUPS="${bastion_allowed_iam_group}"
        IAM_AUTHORIZED_GROUPS_TAG="${bastion_allowed_iam_group_tag}"
        LOCAL_GROUPS=""
        SUDOERS_GROUPS="${bastion_allowed_iam_group}"
        SUDOERS_GROUPS_TAG="${bastion_allowed_iam_group_tag}"
        ASSUMEROLE="${assumerole}"

        # Remove or set to 0 if you are done with configuration
        # To change the interval of the sync change the file
        # /etc/cron.d/import_users
        DONOTSYNC=0
    path: /opt/iam_helper/aws-ec2-ssh.conf
    permissions: '0754'

  -
    content: |
        #!/bin/bash -e

        if [ -z "$$1" ]; then
        exit 1
        fi

        # check if AWS CLI exists
        if ! [ -x "$$(which aws)" ]; then
            echo "aws executable not found - exiting!"
            exit 1
        fi

        # source configuration if it exists
        [ -f /etc/aws-ec2-ssh.conf ] && . /etc/aws-ec2-ssh.conf

        # Assume a role before contacting AWS IAM to get users and keys.
        # This can be used if you define your users in one AWS account, while the EC2
        # instance you use this script runs in another.
        : $${ASSUMEROLE:=""}

        if [[ ! -z "$${ASSUMEROLE}" ]]
        then
        STSCredentials=$$(aws sts assume-role \
            --role-arn "$${ASSUMEROLE}" \
            --role-session-name something \
            --query '[Credentials.SessionToken,Credentials.AccessKeyId,Credentials.SecretAccessKey]' \
            --output text)

        AWS_ACCESS_KEY_ID=$$(echo "$${STSCredentials}" | awk '{print $$2}')
        AWS_SECRET_ACCESS_KEY=$$(echo "$${STSCredentials}" | awk '{print $$3}')
        AWS_SESSION_TOKEN=$$(echo "$${STSCredentials}" | awk '{print $$1}')
        AWS_SECURITY_TOKEN=$$(echo "$${STSCredentials}" | awk '{print $$1}')
        export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_SECURITY_TOKEN
        fi

        UnsaveUserName="$$1"
        UnsaveUserName=$${UnsaveUserName//"plus"/"+"}
        UnsaveUserName=$${UnsaveUserName//"equal"/"="}
        UnsaveUserName=$${UnsaveUserName//"comma"/","}
        UnsaveUserName=$${UnsaveUserName//"at"/"@"}

        aws iam list-ssh-public-keys --user-name "$$UnsaveUserName" --query "SSHPublicKeys[?Status == 'Active'].[SSHPublicKeyId]" --output text | while read -r KeyId; do
        aws iam get-ssh-public-key --user-name "$$UnsaveUserName" --ssh-public-key-id "$$KeyId" --encoding SSH --query "SSHPublicKey.SSHPublicKeyBody" --output text
        done
    path: /opt/sshd_worker/authorized_keys_command.sh
    permissions: '0755'

  -
    content: |
        #!/bin/bash -e

        function log() {
            /usr/bin/logger -i -p auth.info -t aws-ec2-ssh "$$@"
        }

        # check if AWS CLI exists
        if ! [ -x "$$(which aws)" ]; then
            log "aws executable not found - exiting!"
            exit 1
        fi

        # source configuration if it exists
        [ -f /etc/aws-ec2-ssh.conf ] && . /etc/aws-ec2-ssh.conf

        # Should we actually do something?
        : $${DONOTSYNC:=0}

        if [ $${DONOTSYNC} -eq 1 ]
        then
            log "Please configure aws-ec2-ssh by editing /etc/aws-ec2-ssh.conf"
            exit 1
        fi

        # Which IAM groups have access to this instance
        # Comma seperated list of IAM groups. Leave empty for all available IAM users
        : $${IAM_AUTHORIZED_GROUPS:=""}

        # Special group to mark users as being synced by our script
        : $${LOCAL_MARKER_GROUP:="iam-synced-users"}

        # Give the users these local UNIX groups
        : $${LOCAL_GROUPS:=""}

        # Specify an IAM group for users who should be given sudo privileges, or leave
        # empty to not change sudo access, or give it the value '##ALL##' to have all
        # users be given sudo rights.
        # DEPRECATED! Use SUDOERS_GROUPS
        : $${SUDOERSGROUP:=""}

        # Specify a comma seperated list of IAM groups for users who should be given sudo privileges.
        # Leave empty to not change sudo access, or give the value '##ALL## to have all users
        # be given sudo rights.
        : $${SUDOERS_GROUPS:="$${SUDOERSGROUP}"}

        # Assume a role before contacting AWS IAM to get users and keys.
        # This can be used if you define your users in one AWS account, while the EC2
        # instance you use this script runs in another.
        : $${ASSUMEROLE:=""}

        # Possibility to provide a custom useradd program
        : $${USERADD_PROGRAM:="/usr/sbin/useradd"}

        # Possibility to provide custom useradd arguments
        : $${USERADD_ARGS:="--user-group --create-home --shell /bin/bash"}

        # Initizalize INSTANCE variable
        INSTANCE_ID=$$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
        REGION=$$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | grep region | awk -F\" '{print $$4}')

        function setup_aws_credentials() {
            local stscredentials
            if [[ ! -z "$${ASSUMEROLE}" ]]
            then
                stscredentials=$$(aws sts assume-role \
                    --role-arn "$${ASSUMEROLE}" \
                    --role-session-name something \
                    --query '[Credentials.SessionToken,Credentials.AccessKeyId,Credentials.SecretAccessKey]' \
                    --output text)

                AWS_ACCESS_KEY_ID=$$(echo "$${stscredentials}" | awk '{print $$2}')
                AWS_SECRET_ACCESS_KEY=$$(echo "$${stscredentials}" | awk '{print $$3}')
                AWS_SESSION_TOKEN=$$(echo "$${stscredentials}" | awk '{print $$1}')
                AWS_SECURITY_TOKEN=$$(echo "$${stscredentials}" | awk '{print $$1}')
                export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_SECURITY_TOKEN
            fi
        }

        # Get list of iam groups from tag
        function get_iam_groups_from_tag() {
            if [ "$${IAM_AUTHORIZED_GROUPS_TAG}" ]
            then
                IAM_AUTHORIZED_GROUPS=$$(\
                    aws --region $$REGION ec2 describe-tags \
                    --filters "Name=resource-id,Values=$$INSTANCE_ID" "Name=key,Values=$$IAM_AUTHORIZED_GROUPS_TAG" \
                    --query "Tags[0].Value" --output text \
                )
            fi
        }

        # Get all IAM users (optionally limited by IAM groups)
        function get_iam_users() {
            local group
            if [ -z "$${IAM_AUTHORIZED_GROUPS}" ]
            then
                aws iam list-users \
                    --query "Users[].[UserName]" \
                    --output text \
                | sed "s/\r//g"
            else
                for group in $$(echo $${IAM_AUTHORIZED_GROUPS} | tr "," " "); do
                    aws iam get-group \
                        --group-name "$${group}" \
                        --query "Users[].[UserName]" \
                        --output text \
                    | sed "s/\r//g"
                done
            fi
        }

        # Run all found iam users through clean_iam_username
        function get_clean_iam_users() {
            local raw_username

            for raw_username in $$(get_iam_users); do
                clean_iam_username "$${raw_username}" | sed "s/\r//g"
            done
        }

        # Get previously synced users
        function get_local_users() {
            /usr/bin/getent group $${LOCAL_MARKER_GROUP} \
                | cut -d : -f4- \
                | sed "s/,/ /g"
        }

        # Get list of IAM groups marked with sudo access from tag
        function get_sudoers_groups_from_tag() {
            if [ "$${SUDOERS_GROUPS_TAG}" ]
            then
                SUDOERS_GROUPS=$$(\
                    aws --region $$REGION ec2 describe-tags \
                    --filters "Name=resource-id,Values=$$INSTANCE_ID" "Name=key,Values=$$SUDOERS_GROUPS_TAG" \
                    --query "Tags[0].Value" --output text \
                )
            fi
        }

        # Get IAM users of the groups marked with sudo access
        function get_sudoers_users() {
            local group

            [[ -z "$${SUDOERS_GROUPS}" ]] || [[ "$${SUDOERS_GROUPS}" == "##ALL##" ]] ||
                for group in $$(echo "$${SUDOERS_GROUPS}" | tr "," " "); do
                    aws iam get-group \
                        --group-name "$${group}" \
                        --query "Users[].[UserName]" \
                        --output text
                done
        }

        # Get the unix usernames of the IAM users within the sudo group
        function get_clean_sudoers_users() {
            local raw_username

            for raw_username in $$(get_sudoers_users); do
                clean_iam_username "$${raw_username}"
            done
        }

        # Create or update a local user based on info from the IAM group
        function create_or_update_local_user() {
            local username
            local sudousers
            local localusergroups

            username="$${1}"
            sudousers="$${2}"
            localusergroups="$${LOCAL_MARKER_GROUP}"

            # check that username contains only alphanumeric, period (.), underscore (_), and hyphen (-) for a safe eval
            if [[ ! "$${username}" =~ ^[0-9a-zA-Z\._\-]{1,32}$$ ]]
            then
                log "Local user name $${username} contains illegal characters"
                exit 1
            fi

            if [ ! -z "$${LOCAL_GROUPS}" ]
            then
                localusergroups="$${LOCAL_GROUPS},$${LOCAL_MARKER_GROUP}"
            fi

            if ! id "$${username}" >/dev/null 2>&1; then
                $${USERADD_PROGRAM} $${USERADD_ARGS} "$${username}"
                /bin/chown -R "$${username}:$${username}" "$$(eval echo ~$$username)"
                log "Created new user $${username}"
            fi
            /usr/sbin/usermod -a -G "$${localusergroups}" "$${username}"

            # Should we add this user to sudo ?
            if [[ ! -z "$${SUDOERS_GROUPS}" ]]
            then
                SaveUserFileName=$$(echo "$${username}" | tr "." " ")
                SaveUserSudoFilePath="/etc/sudoers.d/$$SaveUserFileName"
                if [[ "$${SUDOERS_GROUPS}" == "##ALL##" ]] || echo "$${sudousers}" | grep "^$${username}\$$" > /dev/null
                then
                    echo "$${username} ALL=(ALL) NOPASSWD:ALL" > "$${SaveUserSudoFilePath}"
                else
                    [[ ! -f "$${SaveUserSudoFilePath}" ]] || rm "$${SaveUserSudoFilePath}"
                fi
            fi
        }

        function delete_local_user() {
            # First, make sure no new sessions can be started
            /usr/sbin/usermod -L -s /sbin/nologin "$${1}" || true
            # ask nicely and give them some time to shutdown
            /usr/bin/pkill -15 -u "$${1}" || true
            sleep 5
            # Dont want to close nicely? DIE!
            /usr/bin/pkill -9 -u "$${1}" || true
            sleep 1
            # Remove account now that all processes for the user are gone
            /usr/sbin/userdel -f -r "$${1}"
            log "Deleted user $${1}"
        }

        function clean_iam_username() {
            local clean_username="$${1}"
            clean_username=$${clean_username//"+"/"plus"}
            clean_username=$${clean_username//"="/"equal"}
            clean_username=$${clean_username//","/"comma"}
            clean_username=$${clean_username//"@"/"at"}
            echo "$${clean_username}"
        }

        function sync_accounts() {
            if [ -z "$${LOCAL_MARKER_GROUP}" ]
            then
                log "Please specify a local group to mark imported users. eg iam-synced-users"
                exit 1
            fi

            # Check if local marker group exists, if not, create it
            /usr/bin/getent group "$${LOCAL_MARKER_GROUP}" >/dev/null 2>&1 || /usr/sbin/groupadd "$${LOCAL_MARKER_GROUP}"

            # setup the aws credentials if needed
            setup_aws_credentials

            # declare and set some variables
            local iam_users
            local sudo_users
            local local_users
            local intersection
            local removed_users
            local user

            # init group and sudoers from tags
            get_iam_groups_from_tag
            get_sudoers_groups_from_tag

            iam_users=$$(get_clean_iam_users | sort | uniq)
            if [[ -z "$${iam_users}" ]]
            then
            log "we just got back an empty iam_users user list which is likely caused by an IAM outage!"
            exit 1
            fi

            sudo_users=$$(get_clean_sudoers_users | sort | uniq)
            if [[ ! -z "$${SUDOERS_GROUPS}" ]] && [[ ! "$${SUDOERS_GROUPS}" == "##ALL##" ]] && [[ -z "$${sudo_users}" ]]
            then
            log "we just got back an empty sudo_users user list which is likely caused by an IAM outage!"
            exit 1
            fi

            local_users=$$(get_local_users | sort | uniq)

            intersection=$$(echo $${local_users} $${iam_users} | tr " " "\n" | sort | uniq -D | uniq)
            removed_users=$$(echo $${local_users} $${intersection} | tr " " "\n" | sort | uniq -u)

            # Add or update the users found in IAM
            for user in $${iam_users}; do
                if [ "$${#user}" -le "32" ]
                then
                    create_or_update_local_user "$${user}" "$$sudo_users"
                else
                    log "Can not import IAM user $${user}. User name is longer than 32 characters."
                fi
            done

            # Remove users no longer in the IAM group(s)
            for user in $${removed_users}; do
                delete_local_user "$${user}"
            done
        }

        sync_accounts

    path: /opt/sshd_worker/import_users.sh
    permissions: '0755'

  -
    content: |
        #!/bin/bash 
        if grep -q '#AuthorizedKeysCommand none' "/etc/ssh/sshd_config"; then
        sed -i "s:#AuthorizedKeysCommand none:AuthorizedKeysCommand /usr/bin/authorized_keys_command.sh:g" "/etc/ssh/sshd_config"
        else
        if ! grep -q "AuthorizedKeysCommand /usr/bin/authorized_keys_command.sh" "/etc/ssh/sshd_config"; then
            echo "AuthorizedKeysCommand /usr/bin/authorized_keys_command.sh" >> "/etc/ssh/sshd_config"
        fi
        fi
        if grep -q '#AuthorizedKeysCommandUser nobody' "/etc/ssh/sshd_config"; then
        sed -i "s:#AuthorizedKeysCommandUser nobody:AuthorizedKeysCommandUser nobody:g" "/etc/ssh/sshd_config"
        else
        if ! grep -q 'AuthorizedKeysCommandUser nobody' "/etc/ssh/sshd_config"; then
            echo "AuthorizedKeysCommandUser nobody" >> "/etc/ssh/sshd_config"
        fi
        fi
        retval=0
        
    path: /opt/sshd_worker/install.sh
    permissions: '0755'
