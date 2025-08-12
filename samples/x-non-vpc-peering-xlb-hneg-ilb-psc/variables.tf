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
  description = "Project id (also used for the Apigee Organization)."
  type        = string
}

variable "billing_account" {
  description = "Billing account id."
  type        = string
  default     = null
}

variable "project_create" {
  description = "Create project. When set to false, uses a data source to reference existing project."
  type        = bool
  default     = false
}

variable "project_parent" {
  description = "Parent folder or organization in 'folders/folder_id' or 'organizations/org_id' format."
  type        = string
  default     = null
  validation {
    condition     = var.project_parent == null || can(regex("(organizations|folders)/[0-9]+", var.project_parent))
    error_message = "Parent must be of the form folders/folder_id or organizations/organization_id."
  }
}

variable "ax_region" {
  description = "GCP region for storing Apigee analytics data (see https://cloud.google.com/apigee/docs/api-platform/get-started/install-cli)."
  type        = string
}

variable "apigee_instances" {
  description = "Apigee Instances (only one instance for EVAL orgs)."
  type = map(object({
    region       = string
    environments = list(string)
  }))
  default = null
}

variable "apigee_envgroups" {
  description = "Apigee Environment Groups."
  type = map(object({
    hostnames = list(string)
  }))
  default = null
}

variable "apigee_environments" {
  description = "Apigee Environments."
  type = map(object({
    display_name = optional(string)
    description  = optional(string)
    node_config = optional(object({
      min_node_count = optional(number)
      max_node_count = optional(number)
    }))
    iam       = optional(map(list(string)))
    envgroups = list(string)
    type      = optional(string)
  }))
  default = null
}

/**
* Below are the variables required for creating XLB -> Hybrid NEG -> Regional ILB -> PSC NEG -> Apigee PSC Service Attachment.
*/

variable "network_name" {
  description = "The name of the VPC network to create."
  type        = string
  default     = "apigee-nb-nw"
}

# Region 1 variables

variable "region1" {
  description = "The GCP region for regional resources (e.g., 'us-central1')."
  type        = string
  default     = "us-east1"
}

variable "region1-zone1" {
  description = "The GCP zone for the Hybrid NEG (e.g., 'us-central1-a'). This should be a zone within the specified region."
  type        = string
  default     = "us-east1-b"
}

variable "region1-subnet-name" {
  description = "The name of the VPC network to create."
  type        = string
  default     = "apigee-nb-nw-subnet-us-east1"
}

variable "region1-subnet-iprange" {
  description = "IP range for region 1 subnet"
  type = string
  default = "10.1.0.0/23"
}

variable "region1-pos-iprange" {
  description = "IP range for region 1 proxy only subnet"
  type = string
  default = "10.3.0.0/23"
}

variable "region1-proxy_only_subnet_name" {
  description = "The name of the proxy-only subnet in the specified region. Required for the Regional Internal Application Load Balancer."
  type        = string
  default     = "apigee-nb-nw-us-east1-pos"
}

variable "region1-psc-neg-name" {
  description = "Name of the region 1 PSC NEG that points to Apigee region 1 Instance"
  type = string
  default = "apigee-us-east1-psc-neg"
}

variable "region1-apigee-psc_target_service_attachment_uri" {
  description = "The URI of the target Service Attachment for the PSC NEG."
  type        = string
  default     = "projects/p54d5feba6873adbap-tp/regions/us-east1/serviceAttachments/apigee-us-east1-giy9"
  # Example: "projects/SERVICE_PRODUCER_PROJECT/regions/REGION/serviceAttachments/MY_SERVICE_ATTACHMENT"
}

variable "region1-ilb-hc-name" {
    description = "Name of region 1 ILB healthcheck"
    type = string
    default = "apigee-us-east1-ilb-hc"
}

variable "region1-ilb-bes-name" {
    description = "Name of the region 1 ILB backend service"
    type = string
    default = "apigee-us-east1-ilb-bes"
}

variable "region1-ilb-port" {
  description = "Port for the Regional Internal Application Load Balancer and Hybrid NEG endpoint (backend communication)."
  type        = number
  default     = 80
}

variable "region1-ilb-urlmap-name" {
  description = "Name of region 1 ILB url map"
  type = string
  default = "apigee-us-east1-ilb-urlmap"
}

variable "region1-ilb-targetproxy-name" {
    description = "Name of region 1 ILB target proxy"
    type = string
    default = "apigee-us-east1-ilb-targetproxy"
}

variable "region1-ilb-ip-name" {
    description = "Name of region 1 ILB IP address"
    type = string
    default = "apigee-us-east1-ilb-ip"
}

variable "region1-ilb-forwardingrule-name" {
    description = "Name of region 1 ILB forwarding rule"
    type = string
    default = "apigee-us-east1-ilb-forwardingrule"
}

variable "region1-hybrid-neg-name" {
    description = "Name of region 1 Hybrid NEG"
    type = string
    default = "apigee-us-east1-hybrid-neg"
}

# Region 2 variables

variable "region2" {
  description = "The GCP region for regional resources (e.g., 'us-central1')."
  type        = string
  default     = "us-west1"
}

variable "region2-zone1" {
  description = "The GCP zone for the Hybrid NEG (e.g., 'us-central1-a'). This should be a zone within the specified region."
  type        = string
  default     = "us-west1-b"
}

variable "region2-subnet-name" {
  description = "The name of the VPC network to create."
  type        = string
  default     = "apigee-nb-nw-subnet-us-west1"
}

variable "region2-subnet-iprange" {
  description = "IP range for region 2 subnet"
  type = string
  default = "10.2.0.0/23"
}

variable "region2-pos-iprange" {
  description = "IP range for region 2 proxy only subnet"
  type = string
  default = "10.4.0.0/23"
}

variable "region2-proxy_only_subnet_name" {
  description = "The name of the proxy-only subnet in the specified region. Required for the Regional Internal Application Load Balancer."
  type        = string
  default     = "apigee-nb-nw-us-west1-pos"
}

variable "region2-psc-neg-name" {
  description = "Name of the region 2 PSC NEG that points to Apigee region 2 Instance"
  type = string
  default = "apigee-us-west1-psc-neg"
}

variable "region2-apigee-psc_target_service_attachment_uri" {
  description = "The URI of the target Service Attachment for the PSC NEG."
  type        = string
  default     = "projects/p54d5feba6873adbap-tp/regions/us-west1/serviceAttachments/apigee-us-west1-eaxq"
  # Example: "projects/SERVICE_PRODUCER_PROJECT/regions/REGION/serviceAttachments/MY_SERVICE_ATTACHMENT"
}

variable "region2-ilb-hc-name" {
    description = "Name of region 2 ILB healthcheck"
    type = string
    default = "apigee-us-west1-ilb-hc"
}

variable "region2-ilb-bes-name" {
    description = "Name of the region 2 ILB backend service"
    type = string
    default = "apigee-us-west1-ilb-bes"
}

variable "region2-ilb-port" {
  description = "Port for the Regional Internal Application Load Balancer and Hybrid NEG endpoint (backend communication)."
  type        = number
  default     = 80
}

variable "region2-ilb-urlmap-name" {
  description = "Name of region 2 ILB url map"
  type = string
  default = "apigee-us-west1-ilb-urlmap"
}

variable "region2-ilb-targetproxy-name" {
    description = "Name of region 2 ILB target proxy"
    type = string
    default = "apigee-us-west1-ilb-targetproxy"
}

variable "region2-ilb-ip-name" {
    description = "Name of region 2 ILB IP address"
    type = string
    default = "apigee-us-west1-ilb-ip"
}

variable "region2-ilb-forwardingrule-name" {
    description = "Name of region 2 ILB forwarding rule"
    type = string
    default = "apigee-us-west1-ilb-forwardingrule"
}

variable "region2-hybrid-neg-name" {
    description = "Name of region 2 Hybrid NEG"
    type = string
    default = "apigee-us-west1-hybrid-neg"
}

# Region 3 variables

variable "region3" {
  description = "The GCP region for regional resources (e.g., 'us-central1')."
  type        = string
  default     = "us-east4"
}

variable "region3-zone1" {
  description = "The GCP zone for the Hybrid NEG (e.g., 'us-central1-a'). This should be a zone within the specified region."
  type        = string
  default     = "us-east4-a"
}

variable "region3-subnet-name" {
  description = "The name of the VPC network to create."
  type        = string
  default     = "apigee-nb-nw-subnet-us-east4"
}

variable "region3-subnet-iprange" {
  description = "IP range for region 3 subnet"
  type = string
  default = "10.5.0.0/23"
}

variable "region3-pos-iprange" {
  description = "IP range for region 3 proxy only subnet"
  type = string
  default = "10.6.0.0/23"
}

variable "region3-proxy_only_subnet_name" {
  description = "The name of the proxy-only subnet in the specified region. Required for the Regional Internal Application Load Balancer."
  type        = string
  default     = "apigee-nb-nw-us-east4-pos"
}

variable "region3-psc-neg-name" {
  description = "Name of the region 3 PSC NEG that points to Apigee region 3 Instance"
  type = string
  default = "apigee-us-east4-psc-neg"
}

variable "region3-apigee-psc_target_service_attachment_uri" {
  description = "The URI of the target Service Attachment for the PSC NEG."
  type        = string
  default     = "projects/p54d5feba6873adbap-tp/regions/us-west1/serviceAttachments/apigee-us-west1-eaxq"
  # Example: "projects/SERVICE_PRODUCER_PROJECT/regions/REGION/serviceAttachments/MY_SERVICE_ATTACHMENT"
}

variable "region3-ilb-hc-name" {
    description = "Name of region 3 ILB healthcheck"
    type = string
    default = "apigee-us-east4-ilb-hc"
}

variable "region3-ilb-bes-name" {
    description = "Name of the region 3 ILB backend service"
    type = string
    default = "apigee-us-east4-ilb-bes"
}

variable "region3-ilb-port" {
  description = "Port for the Regional Internal Application Load Balancer and Hybrid NEG endpoint (backend communication)."
  type        = number
  default     = 80
}

variable "region3-ilb-urlmap-name" {
  description = "Name of region 3 ILB url map"
  type = string
  default = "apigee-us-east4-ilb-urlmap"
}

variable "region3-ilb-targetproxy-name" {
    description = "Name of region 3 ILB target proxy"
    type = string
    default = "apigee-us-east4-ilb-targetproxy"
}

variable "region3-ilb-ip-name" {
    description = "Name of region 3 ILB IP address"
    type = string
    default = "apigee-us-east4-ilb-ip"
}

variable "region3-ilb-forwardingrule-name" {
    description = "Name of region 3 ILB forwarding rule"
    type = string
    default = "apigee-us-east4-ilb-forwardingrule"
}

variable "region3-hybrid-neg-name" {
    description = "Name of region 3 Hybrid NEG"
    type = string
    default = "apigee-us-east4-hybrid-neg"
}

# Region 4 variables

variable "region4" {
  description = "The GCP region for regional resources (e.g., 'us-central1')."
  type        = string
  default     = "us-east5"
}

variable "region4-zone1" {
  description = "The GCP zone for the Hybrid NEG (e.g., 'us-central1-a'). This should be a zone within the specified region."
  type        = string
  default     = "us-east5-b"
}

variable "region4-subnet-name" {
  description = "The name of the VPC network to create."
  type        = string
  default     = "apigee-nb-nw-subnet-us-east5"
}

variable "region4-subnet-iprange" {
  description = "IP range for region 4 subnet"
  type = string
  default = "10.7.0.0/23"
}

variable "region4-pos-iprange" {
  description = "IP range for region 4 proxy only subnet"
  type = string
  default = "10.8.0.0/23"
}

variable "region4-proxy_only_subnet_name" {
  description = "The name of the proxy-only subnet in the specified region. Required for the Regional Internal Application Load Balancer."
  type        = string
  default     = "apigee-nb-nw-us-east5-pos"
}

variable "region4-psc-neg-name" {
  description = "Name of the region 4 PSC NEG that points to Apigee region 2 Instance"
  type = string
  default = "apigee-us-east5-psc-neg"
}

variable "region4-apigee-psc_target_service_attachment_uri" {
  description = "The URI of the target Service Attachment for the PSC NEG."
  type        = string
  default     = "projects/p54d5feba6873adbap-tp/regions/us-west1/serviceAttachments/apigee-us-west1-eaxq"
  # Example: "projects/SERVICE_PRODUCER_PROJECT/regions/REGION/serviceAttachments/MY_SERVICE_ATTACHMENT"
}

variable "region4-ilb-hc-name" {
    description = "Name of region 4 ILB healthcheck"
    type = string
    default = "apigee-us-east5-ilb-hc"
}

variable "region4-ilb-bes-name" {
    description = "Name of the region 4 ILB backend service"
    type = string
    default = "apigee-us-east5-ilb-bes"
}

variable "region4-ilb-port" {
  description = "Port for the Regional Internal Application Load Balancer and Hybrid NEG endpoint (backend communication)."
  type        = number
  default     = 80
}

variable "region4-ilb-urlmap-name" {
  description = "Name of region 4 ILB url map"
  type = string
  default = "apigee-us-east5-ilb-urlmap"
}

variable "region4-ilb-targetproxy-name" {
    description = "Name of region 4 ILB target proxy"
    type = string
    default = "apigee-us-east5-ilb-targetproxy"
}

variable "region4-ilb-ip-name" {
    description = "Name of region 4 ILB IP address"
    type = string
    default = "apigee-us-east5-ilb-ip"
}

variable "region4-ilb-forwardingrule-name" {
    description = "Name of region 4 ILB forwarding rule"
    type = string
    default = "apigee-us-east5-ilb-forwardingrule"
}

variable "region4-hybrid-neg-name" {
    description = "Name of region 4 Hybrid NEG"
    type = string
    default = "apigee-us-east5-hybrid-neg"
}

# External LB variables

variable "apigee-xlb-port" {
  description = "Port for the External HTTPS Application Load Balancer (frontend)."
  type        = number
  default     = 443 # Changed to 443 for HTTPS
}

variable "apigee-xlb-ip-name" {
    description = "Name of static IP for external LB front end"
    type = string
    default = "apigee-xlb-ip"
}

variable "apigee-xlb-ssl-certificate-name" {
    description = "Name of apigee external LB SSL certificate"
    type = string
    default = "apigee-xlb-ssl-certificate"
}

variable "apigee-xlb-hc-tcp-name" {
    description = "Name of apigee external LB healthcheck"
    type = string
    default = "apigee-xlb-hc-tcp"
}

variable "apigee-xlb-bes-name" {
    description = "Name of apigee external LB backend service"
    type = string
    default = "apigee-xlb-bes" 
}

variable "apigee-xlb-urlmap-name" {
    description = "Name of apigee external LB url map"
    type = string
    default = "apigee-xlb-urlmap"
}

variable "apigee-xlb-https-targetproxy-name" {
    description = "Name of apigee external LB target proxy"
    type = string
    default = "apigee-xlb-https-targetproxy"
}

variable "apigee-xlb-https-fwd-rule-name" {
    description = "Name of apigee external LB forwarding rule"
    type = string
    default = "apigee-xlb-https-fwd-rule"
}

variable "apigee_billing_type" {
    default = "EVAL"
  
}

variable "apigee-vpc-fw-xlb-https-ingress-name" {
  description = "Name for VPC firewall rule that allows Internet -> HTTPS into XLB"
  type        = string
  default     = "apigee-vpc-fw-xlb-https-ingress"  
}

variable "apigee-vpc-fw-hneg-http-ingress-name" {
  description = "Name for VPC firewall rule that allows XLB -> HTTP into Hybrid NEG -> Regional ILB"
  type = string
  default = "apigee-vpc-fw-hneg-http-ingress"
}

variable "apigee-vpc-fw-psc-https-egress-name" {
  description = "Name for VPC firewall rule that allows Regional ILB -> HTTPS into PSC NEG -> PSC Service Attachment for Apigee Instance"
  type = string
  default = "apigee-vpc-fw-psc-https-egress"
}

variable "apigee-vpc-fw-allow-health-check-ingress-name" {
  description = "Name for VPC firewall rule that allows IPV4 based GCP health check probes to reach load balancers"
  type = string
  default = "apigee-vpc-fw-allow-health-check-ingress"
}

variable "apigee-vpc-fw-allow-health-check-ipv6-ingress-name" {
  description = "Name for VPC firewall rule that allows IPV6 based GCP health check probes to reach load balancers"
  type = string
  default = "apigee-vpc-fw-allow-health-check-ipv6-ingress"
}

# variable "psc_ingress_network" {
#   description = "PSC ingress VPC name."
#   type        = string
# }

# variable "psc_ingress_subnets" {
#   description = "Subnets for exposing Apigee services via PSC"
#   type = list(object({
#     name               = string
#     ip_cidr_range      = string
#     region             = string
#     secondary_ip_range = map(string)
#   }))
#   default = []
# }
