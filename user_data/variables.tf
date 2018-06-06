variable "environment_name" {
  description = "the name of the environment that we are deploying to"
  default     = "staging"
}

variable "bastion_allowed_iam_group" {
  type        = "string"
  description = "Name of IAM group, members of this group will be able to ssh into bastion instances if they have provided ssh key in their profile. Everyone gets sudo in their container"
  default     = ""
}

variable "vpc" {
  type        = "string"
  description = "the vpc we are deploying to"
}

variable "bastion_allowed_iam_group_tags" {
  description = "Key Tag of EC2 that contains a Comma separated list of IAM groups to import - IAM_AUTHORIZED_GROUPS_TAG will override IAM_AUTHORIZED_GROUPS, you can use only one of them. Everyone gets sudo in their container"
  default     = ""
}

variable "assumerole" {
  description = "IAM Role ARN for multi account"
  default     = ""
}
