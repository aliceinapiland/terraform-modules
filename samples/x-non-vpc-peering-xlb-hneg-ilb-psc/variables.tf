/**
 * Copyright 2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

variable "project_id" {
  description = "The unique identifier for the Google Cloud project. This ID will also be used for the Apigee Organization if project_create is true."
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "Project ID must start with a lowercase letter, followed by 4 to 28 lowercase letters, digits, or hyphens, and end with a lowercase letter or digit."
  }
}

variable "billing_account" {
  description = "The ID of the billing account to associate with the project. Required if project_create is true."
  type        = string
  default     = null
}

variable "project_create" {
  description = "Set to true to create a new Google Cloud project. If false, an existing project_id must be provided."
  type        = bool
  default     = false
}

variable "project_parent" {
  description = "The parent resource for the new project, specified in 'folders/folder_id' or 'organizations/org_id' format. Required if project_create is true."
  type        = string
  default     = null
  validation {
    condition     = var.project_parent == null || can(regex("^(organizations|folders)/[0-9]+$", var.project_parent))
    error_message = "Parent must be of the form folders/folder_id or organizations/organization_id."
  }
}

variable "ax_region" {
  description = "The Google Cloud region for storing Apigee analytics data. See https://cloud.google.com/apigee/docs/api-platform/get-started/install-cli for valid regions."
  type        = string
  validation {
    condition     = can(regex("^[a-z]+-[a-z0-9]+[0-9]$", var.ax_region))
    error_message = "Invalid GCP region format. Must be something like 'us-east1'."
  }
}

variable "apigee_instances" {
  description = "A map of Apigee instances to create. For EVAL organizations, only one instance is typically allowed. Each instance object defines its GCP region and associated environments."
  type = map(object({
    region       = string
    environments = list(string)
  }))
  default = {}
}

variable "apigee_envgroups" {
  description = "A map of Apigee Environment Groups to create. Each group object defines a list of hostnames associated with it."
  type = map(object({
    hostnames = list(string)
  }))
  default = {}
}

variable "apigee_environments" {
  description = "A map of Apigee Environments to create. Each environment object defines properties like display name, description, node configuration, IAM bindings, associated environment groups, and type."
  type = map(object({
    display_name = optional(string)
    description  = optional(string)
    node_config = optional(object({
      min_node_count = optional(number)
      max_node_count = optional(number)
    }))
    iam       = optional(map(list(string)))
    envgroups = list(string)
    type      = optional(string) # APIHUB, CONTROL_PLANE, ANALYTICS_AGENT, CONFIG_DEPLOYMENT, MESSAGE_PROCESSOR
  }))
  default = {}
}

/**
* Networking variables for XLB -> Hybrid NEG -> Regional ILB -> PSC NEG -> Apigee PSC Service Attachment.
*/

variable "region1" {
  description = "The primary GCP region for deploying regional resources like subnets and load balancers (e.g., 'us-east1')."
  type        = string
  default     = "us-east1"
  validation {
    condition     = can(regex("^[a-z]+-[a-z0-9]+[0-9]$", var.region1))
    error_message = "Invalid GCP region format. Must be something like 'us-east1'."
  }
}

variable "region1-zone1" {
  description = "The GCP zone within region1 for deploying zonal resources like the Hybrid NEG (e.g., 'us-east1-b')."
  type        = string
  default     = "us-east1-b"
  validation {
    # Basic check; does not guarantee zone is in region1.
    condition     = can(regex("^[a-z]+-[a-z0-9]+[0-9]-[a-z]$", var.region1-zone1))
    error_message = "Invalid GCP zone format. Must be something like 'us-east1-b'."
  }
}

variable "network_name" {
  description = "The name for the VPC network. Must comply with GCP naming conventions."
  type        = string
  default     = "apigee-nb-nw"
  validation {
    condition     = can(regex("^(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)$", var.network_name))
    error_message = "Invalid network name. Must be a lowercase string between 1 and 63 characters, starting with a letter, and can contain dashes and numbers."
  }
}

variable "region1-subnet-name" {
  description = "The name for the subnet in region1. Must comply with GCP naming conventions."
  type        = string
  default     = "apigee-nb-nw-subnet-us-east1"
  validation {
    condition     = can(regex("^(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)$", var.region1-subnet-name))
    error_message = "Invalid subnet name. Must be a lowercase string between 1 and 63 characters, starting with a letter, and can contain dashes and numbers."
  }
}

variable "region1-subnet-iprange" {
  description = "The primary IPv4 address range for the subnet in region1, in CIDR notation (e.g., '10.1.0.0/23')."
  type        = string
  default     = "10.1.0.0/23"
  validation {
    condition     = can(regex("^(\\d{1,3}\\.){3}\\d{1,3}/(\\d|[1-2]\\d|3[0-2])$", var.region1-subnet-iprange))
    error_message = "Invalid IP CIDR range format. Must be like '10.1.0.0/23'."
  }
}

variable "region1-pos-iprange" {
  description = "The IPv4 address range for the proxy-only subnet in region1, in CIDR notation (e.g., '10.3.0.0/23'). This is used by the Regional Internal Load Balancer."
  type        = string
  default     = "10.3.0.0/23"
  validation {
    condition     = can(regex("^(\\d{1,3}\\.){3}\\d{1,3}/(\\d|[1-2]\\d|3[0-2])$", var.region1-pos-iprange))
    error_message = "Invalid IP CIDR range format. Must be like '10.3.0.0/23'."
  }
}

variable "us-west1-subnet-name" {
  description = "The name for the subnet in the us-west1 region (example for multi-region setup, can be adapted or removed). Must comply with GCP naming conventions."
  type        = string
  default     = "apigee-nb-nw-subnet-us-west1"
  validation {
    condition     = can(regex("^(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)$", var.us-west1-subnet-name))
    error_message = "Invalid subnet name. Must be a lowercase string between 1 and 63 characters, starting with a letter, and can contain dashes and numbers."
  }
}

variable "region1-proxy_only_subnet_name" {
  description = "The name for the proxy-only subnet in region1. Required for the Regional Internal Application Load Balancer. Must comply with GCP naming conventions."
  type        = string
  default     = "apigee-nb-nw-us-east1-pos"
  validation {
    condition     = can(regex("^(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)$", var.region1-proxy_only_subnet_name))
    error_message = "Invalid subnet name. Must be a lowercase string between 1 and 63 characters, starting with a letter, and can contain dashes and numbers."
  }
}

variable "region1-psc-neg-name" {
  description = "Name for the PSC Network Endpoint Group (NEG) in region1 that connects to the Apigee instance's service attachment. Must comply with GCP naming conventions."
  type        = string
  default     = "apigee-us-east1-psc-neg"
  validation {
    condition     = can(regex("^(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)$", var.region1-psc-neg-name))
    error_message = "Invalid PSC NEG name. Must be a lowercase string between 1 and 63 characters, starting with a letter, and can contain dashes and numbers."
  }
}

variable "region1-apigee-psc_target_service_attachment_uri" {
  description = "The URI of the target Apigee Service Attachment for the PSC NEG in region1. Format: 'projects/SERVICE_PRODUCER_PROJECT/regions/REGION/serviceAttachments/MY_SERVICE_ATTACHMENT'."
  type        = string
  default     = "projects/p54d5feba6873adbap-tp/regions/us-east1/serviceAttachments/apigee-us-east1-giy9"
  validation {
    condition     = can(regex("^projects/[^/]+/regions/[^/]+/serviceAttachments/[^/]+$", var.region1-apigee-psc_target_service_attachment_uri))
    error_message = "Invalid Service Attachment URI format. Example: 'projects/sp-project/regions/us-east1/serviceAttachments/sa-name'."
  }
}

variable "region1-ilb-hc-name" {
  description = "Name for the health check used by the Regional Internal Load Balancer (ILB) in region1. Must comply with GCP naming conventions."
  type        = string
  default     = "apigee-us-east1-ilb-hc"
  validation {
    condition     = can(regex("^(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)$", var.region1-ilb-hc-name))
    error_message = "Invalid health check name. Must be a lowercase string between 1 and 63 characters, starting with a letter, and can contain dashes and numbers."
  }
}

variable "region1-ilb-bes-name" {
  description = "Name for the backend service of the Regional ILB in region1. Must comply with GCP naming conventions."
  type        = string
  default     = "apigee-us-east1-ilb-bes"
  validation {
    condition     = can(regex("^(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)$", var.region1-ilb-bes-name))
    error_message = "Invalid backend service name. Must be a lowercase string between 1 and 63 characters, starting with a letter, and can contain dashes and numbers."
  }
}

variable "region1-ilb-port" {
  description = "Port number for the Regional Internal Load Balancer and the Hybrid NEG endpoint for backend communication."
  type        = number
  default     = 80
  validation {
    condition     = var.region1-ilb-port > 0 && var.region1-ilb-port <= 65535
    error_message = "Port number must be between 1 and 65535."
  }
}

variable "region1-ilb-urlmap-name" {
  description = "Name for the URL map of the Regional ILB in region1. Must comply with GCP naming conventions."
  type        = string
  default     = "apigee-us-east1-ilb-urlmap"
  validation {
    condition     = can(regex("^(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)$", var.region1-ilb-urlmap-name))
    error_message = "Invalid URL map name. Must be a lowercase string between 1 and 63 characters, starting with a letter, and can contain dashes and numbers."
  }
}

variable "region1-ilb-targetproxy-name" {
  description = "Name for the target HTTP proxy of the Regional ILB in region1. Must comply with GCP naming conventions."
  type        = string
  default     = "apigee-us-east1-ilb-targetproxy"
  validation {
    condition     = can(regex("^(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)$", var.region1-ilb-targetproxy-name))
    error_message = "Invalid target proxy name. Must be a lowercase string between 1 and 63 characters, starting with a letter, and can contain dashes and numbers."
  }
}

variable "region1-ilb-ip-name" {
  description = "Name for the static internal IP address for the Regional ILB in region1. Must comply with GCP naming conventions."
  type        = string
  default     = "apigee-us-east1-ilb-ip"
  validation {
    condition     = can(regex("^(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)$", var.region1-ilb-ip-name))
    error_message = "Invalid IP address name. Must be a lowercase string between 1 and 63 characters, starting with a letter, and can contain dashes and numbers."
  }
}

variable "region1-ilb-forwardingrule-name" {
  description = "Name for the forwarding rule of the Regional ILB in region1. Must comply with GCP naming conventions."
  type        = string
  default     = "apigee-us-east1-ilb-forwardingrule"
  validation {
    condition     = can(regex("^(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)$", var.region1-ilb-forwardingrule-name))
    error_message = "Invalid forwarding rule name. Must be a lowercase string between 1 and 63 characters, starting with a letter, and can contain dashes and numbers."
  }
}

variable "region1-hybrid-neg-name" {
  description = "Name for the Hybrid Connectivity Network Endpoint Group (NEG) in region1. Must comply with GCP naming conventions."
  type        = string
  default     = "apigee-us-east1-hybrid-neg"
  validation {
    condition     = can(regex("^(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)$", var.region1-hybrid-neg-name))
    error_message = "Invalid Hybrid NEG name. Must be a lowercase string between 1 and 63 characters, starting with a letter, and can contain dashes and numbers."
  }
}


variable "apigee-xlb-port" {
  description = "Port number for the External HTTPS Application Load Balancer (frontend)."
  type        = number
  default     = 443
  validation {
    condition     = var.apigee-xlb-port > 0 && var.apigee-xlb-port <= 65535
    error_message = "Port number must be between 1 and 65535."
  }
}

variable "apigee-xlb-ip-name" {
  description = "Name for the static global IP address used by the External Load Balancer frontend. Must comply with GCP naming conventions."
  type        = string
  default     = "apigee-xlb-ip"
  validation {
    condition     = can(regex("^(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)$", var.apigee-xlb-ip-name))
    error_message = "Invalid IP address name. Must be a lowercase string between 1 and 63 characters, starting with a letter, and can contain dashes and numbers."
  }
}

variable "apigee-xlb-ssl-certificate-name" {
  description = "Name for the SSL certificate used by the External Load Balancer. Must comply with GCP naming conventions."
  type        = string
  default     = "apigee-xlb-ssl-certificate"
  validation {
    condition     = can(regex("^(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)$", var.apigee-xlb-ssl-certificate-name))
    error_message = "Invalid SSL certificate name. Must be a lowercase string between 1 and 63 characters, starting with a letter, and can contain dashes and numbers."
  }
}

variable "apigee-xlb-hc-tcp-name" {
  description = "Name for the TCP health check used by the External Load Balancer. Must comply with GCP naming conventions."
  type        = string
  default     = "apigee-xlb-hc-tcp"
  validation {
    condition     = can(regex("^(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)$", var.apigee-xlb-hc-tcp-name))
    error_message = "Invalid health check name. Must be a lowercase string between 1 and 63 characters, starting with a letter, and can contain dashes and numbers."
  }
}

variable "apigee-xlb-bes-name" {
  description = "Name for the backend service of the External Load Balancer. Must comply with GCP naming conventions."
  type        = string
  default     = "apigee-xlb-bes"
  validation {
    condition     = can(regex("^(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)$", var.apigee-xlb-bes-name))
    error_message = "Invalid backend service name. Must be a lowercase string between 1 and 63 characters, starting with a letter, and can contain dashes and numbers."
  }
}

variable "apigee-xlb-urlmap-name" {
  description = "Name for the URL map of the External Load Balancer. Must comply with GCP naming conventions."
  type        = string
  default     = "apigee-xlb-urlmap"
  validation {
    condition     = can(regex("^(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)$", var.apigee-xlb-urlmap-name))
    error_message = "Invalid URL map name. Must be a lowercase string between 1 and 63 characters, starting with a letter, and can contain dashes and numbers."
  }
}

variable "apigee-xlb-https-targetproxy-name" {
  description = "Name for the HTTPS target proxy of the External Load Balancer. Must comply with GCP naming conventions."
  type        = string
  default     = "apigee-xlb-https-targetproxy"
  validation {
    condition     = can(regex("^(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)$", var.apigee-xlb-https-targetproxy-name))
    error_message = "Invalid target proxy name. Must be a lowercase string between 1 and 63 characters, starting with a letter, and can contain dashes and numbers."
  }
}

variable "apigee-xlb-https-fwd-rule-name" {
  description = "Name for the HTTPS forwarding rule of the External Load Balancer. Must comply with GCP naming conventions."
  type        = string
  default     = "apigee-xlb-https-fwd-rule"
  validation {
    condition     = can(regex("^(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)$", var.apigee-xlb-https-fwd-rule-name))
    error_message = "Invalid forwarding rule name. Must be a lowercase string between 1 and 63 characters, starting with a letter, and can contain dashes and numbers."
  }
}

variable "apigee_billing_type" {
  description = "The billing type for the Apigee organization. Valid values are EVAL, PAYG, SUBSCRIPTION."
  type        = string
  default     = "EVAL"
  validation {
    condition     = contains(["EVAL", "PAYG", "SUBSCRIPTION"], var.apigee_billing_type)
    error_message = "Invalid Apigee billing type. Must be one of: EVAL, PAYG, SUBSCRIPTION."
  }
}

variable "apigee-vpc-fw-xlb-https-ingress-name" {
  description = "Name for the VPC firewall rule allowing HTTPS ingress from the internet to the External Load Balancer. Must comply with GCP naming conventions."
  type        = string
  default     = "apigee-vpc-fw-xlb-https-ingress"
  validation {
    condition     = can(regex("^(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)$", var.apigee-vpc-fw-xlb-https-ingress-name))
    error_message = "Invalid firewall rule name. Must be a lowercase string between 1 and 63 characters, starting with a letter, and can contain dashes and numbers."
  }
}

variable "apigee-vpc-fw-hneg-http-ingress-name" {
  description = "Name for the VPC firewall rule allowing HTTP ingress from the XLB to the Hybrid NEG and Regional ILB. Must comply with GCP naming conventions."
  type        = string
  default     = "apigee-vpc-fw-hneg-http-ingress"
  validation {
    condition     = can(regex("^(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)$", var.apigee-vpc-fw-hneg-http-ingress-name))
    error_message = "Invalid firewall rule name. Must be a lowercase string between 1 and 63 characters, starting with a letter, and can contain dashes and numbers."
  }
}

variable "apigee-vpc-fw-psc-https-egress-name" {
  description = "Name for the VPC firewall rule allowing HTTPS egress from the Regional ILB to the PSC NEG and Apigee instance. Must comply with GCP naming conventions."
  type        = string
  default     = "apigee-vpc-fw-psc-https-egress"
  validation {
    condition     = can(regex("^(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)$", var.apigee-vpc-fw-psc-https-egress-name))
    error_message = "Invalid firewall rule name. Must be a lowercase string between 1 and 63 characters, starting with a letter, and can contain dashes and numbers."
  }
}

variable "apigee-vpc-fw-allow-health-check-ingress-name" {
  description = "Name for the VPC firewall rule allowing IPv4 GCP health check probes to reach load balancers. Must comply with GCP naming conventions."
  type        = string
  default     = "apigee-vpc-fw-allow-health-check-ingress"
  validation {
    condition     = can(regex("^(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)$", var.apigee-vpc-fw-allow-health-check-ingress-name))
    error_message = "Invalid firewall rule name. Must be a lowercase string between 1 and 63 characters, starting with a letter, and can contain dashes and numbers."
  }
}

variable "apigee-vpc-fw-allow-health-check-ipv6-ingress-name" {
  description = "Name for the VPC firewall rule allowing IPv6 GCP health check probes to reach load balancers. Must comply with GCP naming conventions."
  type        = string
  default     = "apigee-vpc-fw-allow-health-check-ipv6-ingress"
  validation {
    condition     = can(regex("^(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)$", var.apigee-vpc-fw-allow-health-check-ipv6-ingress-name))
    error_message = "Invalid firewall rule name. Must be a lowercase string between 1 and 63 characters, starting with a letter, and can contain dashes and numbers."
  }
}

# variable "psc_ingress_network" {
#   description = "The name of the VPC network used for PSC ingress to Apigee services."
#   type        = string
#   # default = "psc-ingress-vpc" # Example default
#   validation {
#     condition     = var.psc_ingress_network == null || can(regex("^(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)$", var.psc_ingress_network))
#     error_message = "Invalid network name. Must be a lowercase string between 1 and 63 characters, starting with a letter, and can contain dashes and numbers."
#   }
# }

# variable "psc_ingress_subnets" {
#   description = "A list of subnets for exposing Apigee services via Private Service Connect (PSC). Each subnet object defines its name, IP CIDR range, region, and optional secondary IP ranges."
#   type = list(object({
#     name               = string # Validate: GCP naming convention
#     ip_cidr_range      = string # Validate: CIDR format
#     region             = string # Validate: GCP region format
#     secondary_ip_range = optional(map(string))
#   }))
#   default = []
#   # Further validation can be added inside the object type if complex rules per field are needed,
#   # or by using a custom validation rule iterating over the list.
# }
