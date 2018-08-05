#Get aws account number
data "aws_caller_identity" "current" {}

#get aws region for use later in plan
data "aws_region" "current" {}

#get list of AWS Availability Zones which can be accessed by an AWS account within the region for use later in plan
data "aws_availability_zones" "available" {}

#get vpc data to whitelist internal CIDR range for Load Balanacer
data "aws_vpc" "main" {
  id = "${var.vpc}"
}

##########################
#Create local for bastion hostname
##########################

locals {
  bastion_vpc_name  = "${var.bastion_vpc_name == "vpc_id" ? var.vpc : var.bastion_vpc_name}"
  bastion_host_name = "${join("-", compact(list(var.environment_name, data.aws_region.current.name, local.bastion_vpc_name)))}"
}

##########################
#Create user-data for bastion ec2 instance 
##########################
locals {
  assume_role_yes = "${var.assume_role_arn != "" ? 1 : 0}"
  assume_role_no  = "${var.assume_role_arn == "" ? 1 : 0}"
}

data "template_file" "user_data_assume_role" {
  count    = "${local.assume_role_yes}"
  template = "${file("${path.module}/user_data/bastion_host_cloudinit_config_assume_role.tpl")}"

  vars {
    bastion_host_name         = "${local.bastion_host_name}"
    authorized_command_code   = "${indent(8, file("${path.module}/user_data/iam_authorized_keys_code/main.go"))}"
    bastion_allowed_iam_group = "${var.bastion_allowed_iam_group}"
    vpc                       = "${var.vpc}"
    assume_role_arn           = "${var.assume_role_arn}"
    container_ubuntu_version  = "${var.container_ubuntu_version}"
  }
}

data "template_file" "user_data_same_account" {
  count    = "${local.assume_role_no}"
  template = "${file("${path.module}/user_data/bastion_host_cloudinit_config.tpl")}"

  vars {
    bastion_host_name         = "${local.bastion_host_name}"
    authorized_command_code   = "${indent(8, file("${path.module}/user_data/iam_authorized_keys_code/main.go"))}"
    bastion_allowed_iam_group = "${var.bastion_allowed_iam_group}"
    vpc                       = "${var.vpc}"
    container_ubuntu_version  = "${var.container_ubuntu_version}"
  }
}

# componentised user data

data "template_cloudinit_config" "user_data_same_account" {
  count         = "${local.assume_role_no}"
  gzip          = false
  base64_encode = false

  part {
    filename     = "module_user_data"
    content_type = "text/x-shellscript"
    content      = "${data.template_file.user_data_same_account.rendered}"
  }

  part {
    filename     = "extra_user_data"
    content_type = "${var.extra_user_data_content_type}"
    content      = "${var.extra_user_data_content}"
    merge_type   = "${var.extra_user_data_merge_type}"
  }
}

data "template_cloudinit_config" "user_data_assume_role" {
  count         = "${local.assume_role_yes}"
  gzip          = false
  base64_encode = false

  part {
    filename     = "module_user_data"
    content_type = "text/x-shellscript"
    content      = "${data.template_file.user_data_assume_role.rendered}"
  }

  part {
    filename     = "extra_user_data"
    content_type = "${var.extra_user_data_content_type}"
    content      = "${var.extra_user_data_content}"
    merge_type   = "${var.extra_user_data_merge_type}"
  }
}

# ##################
# # security group for bastion_service
# ##################

resource "aws_security_group" "bastion_service" {
  name        = "${var.environment_name}-${data.aws_region.current.name}-${var.vpc}-bastion-service"
  description = "Allow access from the SSH Load Balancer to the Bastion Host"

  vpc_id = "${var.vpc}"
  tags   = "${var.tags}"
}

resource "aws_security_group" "bastion_lb" {
  name        = "${var.environment_name}-${data.aws_region.current.name}-${var.vpc}-bastion-lb"
  description = "Allow access from the Internet to the SSH Load Balancer"

  vpc_id = "${var.vpc}"
  tags   = "${var.tags}"
}

##################
# security group rules for bastion_service
##################

# Logic tests for security group rules 

locals {
  hostport_whitelisted = "${(join(",", var.cidr_blocks_whitelist_host) !="") }"
  hostport_healthcheck = "${(var.elb_healthcheck_port == "2222")}"
}

# SSH access in from whitelist IP ranges to Load Balancer

resource "aws_security_group_rule" "lb_ssh_in" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = "${var.cidr_blocks_whitelist_service}"
  security_group_id = "${aws_security_group.bastion_lb.id}"
}

# SSH access in from whitelist IP ranges to Load Balancer (for Bastion Host - conditional)

resource "aws_security_group_rule" "lb_ssh_in_cond" {
  count             = "${(local.hostport_whitelisted ? 1 : 0) }"
  type              = "ingress"
  from_port         = 2222
  to_port           = 2222
  protocol          = "tcp"
  cidr_blocks       = ["${var.cidr_blocks_whitelist_host}"]
  security_group_id = "${aws_security_group.bastion_lb.id}"
}

# Access from Load Balancer to Bastion Host sshd for health check

resource "aws_security_group_rule" "lb_healthcheck_out" {
  count                    = "${((local.hostport_healthcheck || local.hostport_whitelisted) ? 1 : 0) }"
  type                     = "egress"
  from_port                = 2222
  to_port                  = 2222
  protocol                 = "tcp"
  source_security_group_id = "${aws_security_group.bastion_service.id}"
  security_group_id        = "${aws_security_group.bastion_lb.id}"
}

#  Access from Load Balancer to Bastion containers

resource "aws_security_group_rule" "lb_ssh_out" {
  type                     = "egress"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  security_group_id        = "${aws_security_group.bastion_lb.id}"
  source_security_group_id = "${aws_security_group.bastion_service.id}"
}

# SSH access in from Load Balancer to Bastion containers

resource "aws_security_group_rule" "service_ssh_in" {
  type                     = "ingress"
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = "${aws_security_group.bastion_lb.id}"
  security_group_id        = "${aws_security_group.bastion_service.id}"
}

# SSH access in from Load Balancer to Bastion Host 

resource "aws_security_group_rule" "host_ssh_in" {
  count                    = "${((local.hostport_healthcheck || local.hostport_whitelisted) ? 1 : 0) }"
  type                     = "ingress"
  from_port                = 2222
  to_port                  = 2222
  protocol                 = "tcp"
  source_security_group_id = "${aws_security_group.bastion_lb.id}"
  security_group_id        = "${aws_security_group.bastion_service.id}"
}

# Permissive egress policy because we want users to be able to install their own packages 

resource "aws_security_group_rule" "bastion_host_out" {
  type              = "egress"
  from_port         = 0
  to_port           = 65535
  protocol          = -1
  security_group_id = "${aws_security_group.bastion_service.id}"
  cidr_blocks       = ["0.0.0.0/0"]
}

##########################
#Query for most recent AMI of type Amazon Linux for use as host
##########################

data "aws_ami" "amazon-linux-2" {
  most_recent = true

  filter {
    name   = "owner-alias"
    values = ["amazon"]
  }

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm*gp2"]
  }
}

############################
#Launch configuration for service host
############################

resource "aws_launch_configuration" "bastion-service-host-local" {
  count                       = "${local.assume_role_no}"
  name_prefix                 = "bastion-service-host"
  image_id                    = "${data.aws_ami.amazon-linux-2.id}"
  instance_type               = "${var.bastion_instance_type}"
  iam_instance_profile        = "${aws_iam_instance_profile.bastion_service_profile.arn}"
  associate_public_ip_address = "false"
  security_groups             = ["${aws_security_group.bastion_service.id}"]

  user_data = "${element(
    concat(data.template_cloudinit_config.user_data_assume_role.*.rendered,
           data.template_cloudinit_config.user_data_same_account.*.rendered),
    0)}"

  key_name = "${var.bastion_service_host_key_name}"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_launch_configuration" "bastion-service-host-assume" {
  count                       = "${local.assume_role_yes}"
  name_prefix                 = "bastion-service-host"
  image_id                    = "${data.aws_ami.amazon-linux-2.id}"
  instance_type               = "${var.bastion_instance_type}"
  iam_instance_profile        = "${aws_iam_instance_profile.bastion_service_assume_role_profile.arn}"
  associate_public_ip_address = "false"
  security_groups             = ["${aws_security_group.bastion_service.id}"]

  user_data = "${element(
    concat(data.template_cloudinit_config.user_data_assume_role.*.rendered,
           data.template_cloudinit_config.user_data_same_account.*.rendered),
    0)}"

  key_name = "${var.bastion_service_host_key_name}"

  lifecycle {
    create_before_destroy = true
  }
}

#######################################################
# ASG section
#######################################################

resource "aws_autoscaling_group" "bastion-service-asg-local" {
  count                = "${local.assume_role_no}"
  availability_zones   = ["${data.aws_availability_zones.available.names}"]
  name_prefix          = "bastion-service-asg"
  max_size             = "${var.asg_max}"
  min_size             = "${var.asg_min}"
  desired_capacity     = "${var.asg_desired}"
  launch_configuration = "${aws_launch_configuration.bastion-service-host-local.name}"
  vpc_zone_identifier  = ["${var.subnets_asg}"]
  load_balancers       = ["${aws_elb.bastion-service-elb.name}"]

  lifecycle {
    create_before_destroy = true
  }

  tags = [{
    key                 = "Name"
    value               = "${var.environment_name}-${data.aws_region.current.name}-${var.vpc}-bastion"
    propagate_at_launch = true
  },
    {
      key                 = "Environment"
      value               = "${var.environment_name}"
      propagate_at_launch = true
    },
    {
      key                 = "Region"
      value               = "data.aws_region.current.name"
      propagate_at_launch = true
    },
  ]
}

resource "aws_autoscaling_group" "bastion-service-asg-assume" {
  count                = "${local.assume_role_yes}"
  availability_zones   = ["${data.aws_availability_zones.available.names}"]
  name_prefix          = "bastion-service-asg"
  max_size             = "${var.asg_max}"
  min_size             = "${var.asg_min}"
  desired_capacity     = "${var.asg_desired}"
  launch_configuration = "${aws_launch_configuration.bastion-service-host-assume.name}"
  vpc_zone_identifier  = ["${var.subnets_asg}"]
  load_balancers       = ["${aws_elb.bastion-service-elb.name}"]

  lifecycle {
    create_before_destroy = true
  }

  tags = [{
    key                 = "Name"
    value               = "${var.environment_name}-${data.aws_region.current.name}-${var.vpc}-bastion"
    propagate_at_launch = true
  },
    {
      key                 = "Environment"
      value               = "${var.environment_name}"
      propagate_at_launch = true
    },
    {
      key                 = "Region"
      value               = "data.aws_region.current.name"
      propagate_at_launch = true
    },
  ]
}

#######################################################
# ELB section
#######################################################

resource "aws_elb" "bastion-service-elb" {
  name = "bastion-${var.vpc}"

  # Sadly can't use availabilty zones for classic load balancer - see https://github.com/terraform-providers/terraform-provider-aws/issues/1063
  subnets = ["${var.subnets_elb}"]

  security_groups = ["${aws_security_group.bastion_lb.id}"]

  listener {
    instance_port     = 22
    instance_protocol = "TCP"
    lb_port           = 22
    lb_protocol       = "TCP"
  }

  listener {
    instance_port     = 2222
    instance_protocol = "TCP"
    lb_port           = 2222
    lb_protocol       = "TCP"
  }

  health_check {
    healthy_threshold   = "${var.elb_healthy_threshold}"
    unhealthy_threshold = "${var.elb_unhealthy_threshold}"
    timeout             = "${var.elb_timeout}"
    target              = "TCP:${var.elb_healthcheck_port}"
    interval            = "${var.elb_interval}"
  }

  cross_zone_load_balancing   = true
  idle_timeout                = "${var.elb_idle_timeout}"
  connection_draining         = true
  connection_draining_timeout = 300
}

####################################################
# DNS Section
###################################################

resource "aws_route53_record" "bastion_service" {
  count   = "${(var.route53_zone_id !="" ? 1 : 0) }"
  zone_id = "${var.route53_zone_id}"
  name    = "${local.bastion_host_name}-bastion-service.${var.dns_domain}"
  type    = "A"

  alias {
    name                   = "${aws_elb.bastion-service-elb.dns_name}"
    zone_id                = "${aws_elb.bastion-service-elb.zone_id}"
    evaluate_target_health = true
  }
}

####################################################
# sample policy for parent account
###################################################

data "template_file" "sample_policies_for_parent_account" {
  count    = "${local.assume_role_yes}"
  template = "${file("${path.module}/sts_assumerole_example/policy_example.tpl")}"

  vars {
    aws_profile               = "${var.aws_profile}"
    bastion_allowed_iam_group = "${var.bastion_allowed_iam_group}"
    assume_role_arn           = "${var.assume_role_arn}"
  }
}
