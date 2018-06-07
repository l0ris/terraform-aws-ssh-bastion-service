# output "user_data_bastion" {
#   description = "cloud-config user data used to initialize bastion at start up"
#   value       = "${data.template_file.bastion_host.rendered}"
# }

output "service_dns_entry" {
  description = "dns-registered url for service and host"
  value       = "${var.environment_name}-${var.aws_region}-${data.aws_vpc.main.id}-bastion-service.${var.dns_domain}"
}
