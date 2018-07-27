#!/bin/bash
cat <<EOF >> /opt/sshd_worker/Dockerfile
FROM ubuntu:${container_ubuntu_version}

RUN apt-get update && apt-get install -y openssh-server sudo awscli && echo '\033[1;31mI am a one-time Ubuntu container with passwordless sudo. \033[1;37;41mI will terminate after 12 hours or else on exit\033[0m' > /etc/motd && mkdir /var/run/sshd

EXPOSE 22
CMD ["/opt/ssh_populate.sh"]
EOF
cat <<EOF >> /opt/iam_helper/ssh_populate.sh
#!/bin/bash
KST=(`aws sts assume-role --role-arn "${assume_role_arn}" --role-session-name $(hostname) --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text`)
export AWS_ACCESS_KEY_ID=$${KST[0]}; export AWS_SECRET_ACCESS_KEY=$${KST[1]}; export AWS_SESSION_TOKEN=$${KST[2]}
(
count=1
/opt/iam-authorized-keys-command | while read line
do
  username=$( echo $line | sed -e 's/^# //' -e 's/+/plus/' -e 's/=/equal/' -e 's/,/comma/' -e 's/@/at/' )
  useradd -m -s /bin/bash -k /etc/skel $username
  usermod -a -G sudo $username
  echo $username\ 'ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/$count
  chmod 0440 /etc/sudoers.d/$count
  count=$(( $count + 1 ))
  mkdir /home/$username/.ssh
  read line2
  echo $line2 >> /home/$username/.ssh/authorized_keys
  chown -R $username:$username /home/$username/.ssh
  chmod 700 /home/$username/.ssh
  chmod 0600 /home/$username/.ssh/authorized_keys
done

) > /dev/null 2>&1

/usr/sbin/sshd -i
EOF
chmod 0754 /opt/iam_helper/ssh_populate.sh
cat <<EOF >> /etc/systemd/system/sshd_worker.socket
[Unit]
Description=SSH Socket for Per-Connection docker ssh container

[Socket]
ListenStream=22
Accept=true

[Install]
WantedBy=sockets.target
cat <<EOF >> /etc/systemd/system/sshd_worker@.service
[Unit]
Description=SSH Per-Connection docker ssh container

[Service]
Type=simple
ExecStart= /usr/bin/docker run --rm -i --hostname ${bastion_host_name}_%i -v /dev/log:/dev/log -v /opt/iam_helper:/opt:ro sshd_worker
StandardInput=socket
RuntimeMaxSec=43200

[Install]
WantedBy=multi-user.target
EOF
cat <<EOF >> /opt/golang/src/iam-authorized-keys-command/main.go
${authorized_command_code}
EOF
chmod 0754 /opt/golang/src/iam-authorized-keys-command/main.go
#!/bin/bash
#debian specific set up for docker https://docs.docker.com/install/linux/docker-ce/debian/#install-using-the-repository
yum install -y docker
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
# mkdir /opt/iam_helper

# build iam-authorized-keys-command
yum install -y golang
export GOPATH=/opt/golang

COMMAND_DIR=$GOPATH/src/iam-authorized-keys-command

mkdir -p $COMMAND_DIR
cd $COMMAND_DIR

go get ./...
go build -ldflags "-X main.iamGroup=${bastion_allowed_iam_group}" -o /opt/iam_helper/iam-authorized-keys-command ./main.go

chown root /opt/iam_helper
chmod -R 700 /opt/iam_helper
#set hostname to match dns
hostnamectl set-hostname ${bastion_host_name}-${vpc}-bastion-host
sed -e '/127.0.0.1/s/$/ ${bastion_host_name}-bastion-host/' -i /etc/hosts