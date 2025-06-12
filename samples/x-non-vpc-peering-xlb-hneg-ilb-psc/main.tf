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

# ------------------------------------------------------------------------------
# PROVIDER CONFIGURATION
# ------------------------------------------------------------------------------
terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region1 # Default region for provider operations
}

# ------------------------------------------------------------------------------
# LOCALS
# ------------------------------------------------------------------------------
locals {
  project_id                       = var.project_id
  region1                          = var.region1
  region1_zone1                    = var.region1-zone1
  network_self_link                = google_compute_network.main_network.self_link
  region1_subnet_self_link         = google_compute_subnetwork.region1-subnet.self_link
  apigee_xlb_ip_address            = google_compute_global_address.apigee-xlb-ip.address
  region1_ilb_ip_address           = google_compute_address.region1-ilb-ip.address # Source IP for ILB
  nip_io_domain                    = "${local.apigee_xlb_ip_address}.nip.io"
  health_check_source_ranges_ipv4  = ["35.191.0.0/16", "130.211.0.0/22", "209.85.152.0/22", "209.85.204.0/22"]
  apigee_instance_service_attachment_region1 = module.apigee-x-core.instance_service_attachments[local.region1]
  apigee_xlb_ip_address_with_mask  = "${local.apigee_xlb_ip_address}/32"
  region1_ilb_ip_address_with_mask = "${local.region1_ilb_ip_address}/32"
}

# ------------------------------------------------------------------------------
# PROJECT SETUP (Optional: Create project and enable APIs)
# ------------------------------------------------------------------------------
module "project" {
  source          = "github.com/terraform-google-modules/cloud-foundation-fabric//modules/project?ref=v28.0.0"
  name            = local.project_id
  parent          = var.project_parent
  billing_account = var.billing_account
  project_create  = var.project_create
  services = [
    "cloudresourcemanager.googleapis.com",
    "apigee.googleapis.com",
    "cloudkms.googleapis.com",
    "compute.googleapis.com",
    "servicenetworking.googleapis.com" # Required for Apigee X provisioning
  ]
}

# ------------------------------------------------------------------------------
# APIGEE X CORE MODULE
# Deploys Apigee X organization, instances, environments, and environment groups.
# ------------------------------------------------------------------------------
module "apigee-x-core" {
  source              = "../../modules/apigee-x-core"
  project_id          = module.project.project_id # Ensures project is ready
  apigee_environments = var.apigee_environments
  ax_region           = var.ax_region
  apigee_envgroups = {
    for name, env_group in var.apigee_envgroups : name => {
      hostnames = concat(env_group.hostnames, [local.nip_io_domain])
    }
  }
  apigee_instances    = var.apigee_instances
  disable_vpc_peering = true # We are using PSC, so VPC peering is not needed
}

# ------------------------------------------------------------------------------
# VPC NETWORK & SUBNETS
# Creates the Virtual Private Cloud (VPC) network and necessary subnets.
# ------------------------------------------------------------------------------
resource "google_compute_network" "main_network" {
  project                 = local.project_id
  name                    = var.network_name
  description             = "The northbound VPC network for Apigee X traffic."
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "region1-subnet" {
  project               = local.project_id
  name                  = var.region1-subnet-name
  region                = local.region1
  network               = local.network_self_link
  ip_cidr_range         = var.region1-subnet-iprange
  private_ip_google_access = true
}

resource "google_compute_subnetwork" "region1-proxy_only_subnet" {
  project       = local.project_id
  name          = var.region1-proxy_only_subnet_name
  region        = local.region1
  network       = local.network_self_link
  ip_cidr_range = var.region1-pos-iprange
  purpose       = "REGIONAL_MANAGED_PROXY" # Required for Regional HTTP(S) Load Balancers
  role          = "ACTIVE"
}

# ------------------------------------------------------------------------------
# PSC NETWORK ENDPOINT GROUP (NEG) - For Apigee Instance
# Connects the Regional ILB to the Apigee instance in region1 via its Service Attachment.
# ------------------------------------------------------------------------------
resource "google_compute_region_network_endpoint_group" "region1-psc_neg" {
  project                  = local.project_id
  name                     = var.region1-psc-neg-name
  region                   = local.region1
  network                  = local.network_self_link
  subnetwork               = local.region1_subnet_self_link
  network_endpoint_type    = "PRIVATE_SERVICE_CONNECT"
  psc_target_service       = local.apigee_instance_service_attachment_region1
  lifecycle {
    create_before_destroy = true # Recommended for NEGs to avoid downtime during updates
  }
}

# ------------------------------------------------------------------------------
# REGIONAL INTERNAL L7 LOAD BALANCER (ILB)
# Forwards traffic from the Hybrid NEG to the PSC NEG (Apigee).
# Listens on var.region1-ilb-port (typically HTTP/80).
# ------------------------------------------------------------------------------

# ILB Components:
# 1. Static Internal IP Address
# 2. Backend Service (pointing to PSC NEG)
# 3. URL Map
# 4. Target HTTP Proxy
# 5. Forwarding Rule

## Internal IP Address for ILB
resource "google_compute_address" "region1-ilb-ip" {
  project      = local.project_id
  name         = var.region1-ilb-ip-name
  region       = local.region1
  subnetwork   = local.region1_subnet_self_link
  address_type = "INTERNAL"
}

## Regional Backend Service for ILB
resource "google_compute_region_backend_service" "region1-ilb-bes" {
  project                  = local.project_id
  name                     = var.region1-ilb-bes-name
  region                   = local.region1
  protocol                 = "HTTPS" # Protocol between ILB and PSC NEG. Assumes Apigee endpoint is HTTPS.
  load_balancing_scheme    = "INTERNAL_MANAGED"
  # health_checks            = [google_compute_region_health_check.region1-ilb-hc.id] # Optional: Add if specific health check is defined

  backend {
    group          = google_compute_region_network_endpoint_group.region1-psc_neg.id
    balancing_mode = "UTILIZATION" # Or CONNECTION, depending on traffic patterns
  }
}

## Regional URL Map for ILB
resource "google_compute_region_url_map" "region1-ilb-urlmap" {
  project         = local.project_id
  name            = var.region1-ilb-urlmap-name
  region          = local.region1
  default_service = google_compute_region_backend_service.region1-ilb-bes.id
}

## Regional Target HTTP Proxy for ILB
resource "google_compute_region_target_http_proxy" "region1-ilb-targetproxy" {
  project = local.project_id
  name    = var.region1-ilb-targetproxy-name
  region  = local.region1
  url_map = google_compute_region_url_map.region1-ilb-urlmap.id
}

## Regional Forwarding Rule for ILB
resource "google_compute_forwarding_rule" "region1-ilb-forwardingrule" {
  project               = local.project_id
  name                  = var.region1-ilb-forwardingrule-name
  region                = local.region1
  ip_address            = local.region1_ilb_ip_address # Reference the created internal IP
  ip_protocol           = "TCP"                        # Standard for HTTP/HTTPS LBs
  load_balancing_scheme = "INTERNAL_MANAGED"
  all_ports             = false
  port_range            = var.region1-ilb-port # e.g., 80 for HTTP
  target                = google_compute_region_target_http_proxy.region1-ilb-targetproxy.id
  network               = local.network_self_link
  subnetwork            = local.region1_subnet_self_link
  network_tier          = "PREMIUM" # Standard tier for regional LBs
  allow_global_access   = false     # Restrict access to within the region
}

# ------------------------------------------------------------------------------
# HYBRID NETWORK ENDPOINT GROUP (NEG)
# Exposes the Regional ILB's IP and port as a "non-GCP" endpoint for the External XLB.
# ------------------------------------------------------------------------------

## Hybrid NEG in region1/zone1
resource "google_compute_network_endpoint_group" "region1-hybrid-neg" {
  project                 = local.project_id
  name                    = var.region1-hybrid-neg-name
  zone                    = local.region1_zone1 # Hybrid NEGs are zonal
  network                 = local.network_self_link
  network_endpoint_type   = "NON_GCP_PRIVATE_IP_PORT" # Key for Hybrid NEG
  default_port            = var.region1-ilb-port      # The port the ILB is listening on (e.g., 80)
}

## Network Endpoint for the Hybrid NEG (pointing to ILB's IP/Port)
resource "google_compute_network_endpoint" "region1-hybrid-neg-endpoint" {
  project                 = local.project_id
  network_endpoint_group  = google_compute_network_endpoint_group.region1-hybrid-neg.name # Use .name for direct reference
  zone                    = local.region1_zone1
  ip_address              = local.region1_ilb_ip_address # IP of the ILB Forwarding Rule
  port                    = var.region1-ilb-port         # Port of the ILB
}

# ------------------------------------------------------------------------------
# GLOBAL EXTERNAL L7 LOAD BALANCER (XLB)
# Exposes Apigee services to the internet.
# Forwards traffic to the Hybrid NEG (which points to the Regional ILB).
# ------------------------------------------------------------------------------

# XLB Components:
# 1. Global Static IP Address
# 2. SSL Certificate (Google-managed or self-managed)
# 3. Health Check (for Hybrid NEG endpoint)
# 4. Backend Service (pointing to Hybrid NEG)
# 5. URL Map
# 6. Target HTTPS Proxy
# 7. Global Forwarding Rule

## Global Static IP Address for XLB
resource "google_compute_global_address" "apigee-xlb-ip" {
  project = local.project_id
  name    = var.apigee-xlb-ip-name
  # address_type = "EXTERNAL" # Default is EXTERNAL
}

## Google-managed SSL Certificate for XLB
# DNS A/AAAA records for the domains must point to local.apigee_xlb_ip_address for provisioning.
resource "google_compute_managed_ssl_certificate" "apigee-xlb-ssl-certificate" {
  count = 1 # Conditional creation, assumes always needed for now

  project = local.project_id
  name    = var.apigee-xlb-ssl-certificate-name
  managed {
    domains = [local.nip_io_domain] # Uses the nip.io domain based on the XLB's IP
  }
}

## Global Health Check for XLB's Backend Service (Hybrid NEG)
# This health check targets the ILB's port and protocol via the Hybrid NEG.
resource "google_compute_health_check" "apigee-xlb-hc-tcp" {
  project = local.project_id
  name    = var.apigee-xlb-hc-tcp-name
  # Using TCP health check as Hybrid NEG endpoints are non-GCP.
  # Ensure the ILB at local.region1_ilb_ip_address:var.region1-ilb-port is reachable and responsive from GCP health checkers.
  tcp_health_check {
    port = var.region1-ilb-port # Health check targets the ILB's listening port
  }
  timeout_sec         = 5
  check_interval_sec  = 5 # Standard intervals
  healthy_threshold   = 2
  unhealthy_threshold = 2
}

## Global Backend Service for XLB (pointing to Hybrid NEG)
resource "google_compute_backend_service" "apigee-xlb-bes" {
  project                  = local.project_id
  name                     = var.apigee-xlb-bes-name
  protocol                 = "HTTP" # Protocol from XLB to Hybrid NEG (ILB). SSL is terminated at XLB.
  port_name                = "http" # Must match a named port if used, otherwise corresponds to default_port of NEG.
  load_balancing_scheme    = "EXTERNAL_MANAGED"
  health_checks            = [google_compute_health_check.apigee-xlb-hc-tcp.id]

  backend {
    group                   = google_compute_network_endpoint_group.region1-hybrid-neg.id # Points to the Hybrid NEG
    balancing_mode          = "RATE"      # Good for HTTP(S) traffic
    max_rate_per_endpoint   = 100         # Requests per second per endpoint
  }
}

## Global URL Map for XLB
resource "google_compute_url_map" "apigee-xlb-urlmap" {
  project         = local.project_id
  name            = var.apigee-xlb-urlmap-name
  default_service = google_compute_backend_service.apigee-xlb-bes.id
}

## Global Target HTTPS Proxy for XLB
resource "google_compute_target_https_proxy" "apigee-xlb-targetproxy" {
  count = 1 # Conditional creation

  project          = local.project_id
  name             = var.apigee-xlb-https-targetproxy-name
  url_map          = google_compute_url_map.apigee-xlb-urlmap.id
  ssl_certificates = [google_compute_managed_ssl_certificate.apigee-xlb-ssl-certificate[0].self_link]
  # ssl_policy     = var.ssl_policy # Optional: Specify an SSL policy
}

## Global Forwarding Rule for XLB
resource "google_compute_global_forwarding_rule" "external_lb_forwarding_rule" {
  count = 1 # Conditional creation

  project               = local.project_id
  name                  = var.apigee-xlb-https-fwd-rule-name
  ip_protocol           = "TCP" # Standard for HTTPS LBs
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = var.apigee-xlb-port # e.g., 443 for HTTPS
  target                = google_compute_target_https_proxy.apigee-xlb-targetproxy[0].id
  ip_address            = local.apigee_xlb_ip_address # The global static IP
  network_tier          = "PREMIUM"                   # Required for global LBs
}

# ------------------------------------------------------------------------------
# FIREWALL RULES
# Configures VPC firewall rules to allow necessary traffic flows.
# ------------------------------------------------------------------------------

## Allow HTTPS from Internet to XLB
resource "google_compute_firewall" "apigee-vpc-fw-xlb-https-ingress" {
  project     = local.project_id
  name        = var.apigee-vpc-fw-xlb-https-ingress-name
  network     = local.network_self_link
  direction   = "INGRESS"
  description = "Allow HTTPS traffic from the Internet to the External Load Balancer."
  allow {
    protocol = "tcp"
    ports    = [var.apigee-xlb-port] # Typically 443
  }
  source_ranges      = ["0.0.0.0/0"] # From anywhere on the internet
  destination_ranges = [local.apigee_xlb_ip_address_with_mask]
  # target_tags applicable if your XLB forwarding rule has target tags; not typical for global forwarding rules.
}

## Allow HTTP/S from XLB to Hybrid NEG (ILB)
resource "google_compute_firewall" "apigee-vpc-fw-xlb-to-hybrid-neg-ingress" { # Name in var is apigee-vpc-fw-hneg-http-ingress-name
  project     = local.project_id
  name        = var.apigee-vpc-fw-hneg-http-ingress-name
  network     = local.network_self_link
  direction   = "INGRESS"
  description = "Allow traffic from Google Front Ends (GFE)/XLB to the Hybrid NEG, which fronts the Regional ILB."
  allow {
    protocol = "tcp"
    ports    = [var.region1-ilb-port] # Port the ILB (via Hybrid NEG) listens on
  }
  source_ranges      = local.health_check_source_ranges_ipv4 # GFEs use these ranges too
  destination_ranges = [var.region1-subnet-iprange] # Subnet of the ILB
  # If ILB IP is static and known, can use local.region1_ilb_ip_address_with_mask
}

## Allow HTTPS from ILB to PSC NEG (Apigee Instance)
resource "google_compute_firewall" "apigee-vpc-fw-ilb-to-psc-neg-egress" {
  project       = local.project_id
  name          = var.apigee-vpc-fw-psc-https-egress-name # Name in var is apigee-vpc-fw-psc-https-egress-name
  network       = local.network_self_link
  direction     = "EGRESS"
  description   = "Allow HTTPS traffic from the Regional ILB to the PSC NEG targeting Apigee Service Attachment."
  allow {
    protocol = "tcp"
    ports    = ["443"] # Apigee's service attachment listens on 443
  }
  source_ranges      = [local.region1_ilb_ip_address_with_mask] # Egress from the ILB's IP
  # Destination for PSC is generally within Google's private ranges used by Service Networking.
  # Using a broad range like "10.0.0.0/8" is a common practice when the specific target subnets of the service producer are not known or fixed.
  destination_ranges = ["10.0.0.0/8"]
}

## Allow GCP Health Checks (IPv4) to Load Balancers
resource "google_compute_firewall" "apigee-vpc-fw-allow-health-check-ingress" { # Name in var is apigee-vpc-fw-allow-health-check-ingress-name
  project     = local.project_id
  name        = var.apigee-vpc-fw-allow-health-check-ingress-name
  network     = local.network_self_link
  direction   = "INGRESS"
  description = "Allow IPv4 GCP health check probes to reach load balancers (XLB and ILB)."
  allow {
    protocol = "tcp" # Health checks are typically TCP, can be specific ports if needed
    # ports are implicitly covered by the health check definitions, but can be specified.
  }
  source_ranges      = local.health_check_source_ranges_ipv4
  # Destination should cover both XLB and ILB IPs if they are health checked directly.
  # Hybrid NEG is health checked on ILB IP. PSC NEG is health checked by ILB.
  destination_ranges = [local.apigee_xlb_ip_address_with_mask, local.region1_ilb_ip_address_with_mask]
  # target_tags can be used if your instances/NEGs are tagged for health checks.
}

  # Note: IPv6 health check firewall rule (var.apigee-vpc-fw-allow-health-check-ipv6-ingress-name from variables.tf)
  # is not implemented here as the current setup does not include IPv6 configurations for the XLB.
  # To enable IPv6 health checks for an XLB with an IPv6 address:
  # 1. Uncomment the variable "apigee-vpc-fw-allow-health-check-ipv6-ingress-name" in variables.tf.
  # 2. Ensure your XLB (google_compute_global_forwarding_rule.external_lb_forwarding_rule) is configured with an IPv6 address.
  #    This typically involves setting `ip_version = "IPV6"` on the forwarding rule and using a global IPv6 address.
  # 3. Define a local, e.g., `local.apigee_xlb_ipv6_address_with_mask`, similar to the IPv4 version.
  # 4. Uncomment and configure the resource block below.
  # resource "google_compute_firewall" "apigee-vpc-fw-allow-health-check-ipv6-ingress" {
  #   project            = local.project_id
  #   name               = var.apigee-vpc-fw-allow-health-check-ipv6-ingress-name
  #   network            = local.network_self_link
  #   direction          = "INGRESS"
  #   description        = "Allow IPv6 health checks from Google Cloud to XLB."
  #   allow { protocol   = "tcp" } # Health checks use TCP
  #   source_ranges      = ["2600:2d00:1:1::/64"] # Google's IPv6 Health Check Range for GCLB
  #   destination_ranges = [local.apigee_xlb_ipv6_address_with_mask] # XLB's IPv6 address with /128 mask
  # }
