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
  region  = var.region1
}

module "project" {
  source          = "github.com/terraform-google-modules/cloud-foundation-fabric//modules/project?ref=v28.0.0"
  name            = var.project_id
  parent          = var.project_parent
  billing_account = var.billing_account
  project_create  = var.project_create
  services = [
    "cloudresourcemanager.googleapis.com",
    "apigee.googleapis.com",
    "cloudkms.googleapis.com",
    "compute.googleapis.com"
  ]
}

## 6a. Global Static IP Address for External LB
resource "google_compute_global_address" "apigee-xlb-ip" {
  project = var.project_id
  name    = var.apigee-xlb-ip-name
}

module "apigee-x-core" {
  source              = "../../modules/apigee-x-core"
  project_id          = module.project.project_id
  apigee_environments = var.apigee_environments
  ax_region           = var.ax_region
  apigee_envgroups = {
    for name, env_group in var.apigee_envgroups : name => {
      hostnames = concat(env_group.hostnames, ["${google_compute_global_address.apigee-xlb-ip.address}.nip.io"])
    }
  }
  apigee_instances    = var.apigee_instances
  disable_vpc_peering = true
}


# ------------------------------------------------------------------------------
# 1. VPC
#    Create apigee northbound VPC
# ------------------------------------------------------------------------------

resource "google_compute_network" "main_network" {
  name = var.network_name
  project = var.project_id
  description = "The northbound VPC network to use with the Apigee deployment"
  auto_create_subnetworks = false
}

# ------------------------------------------------------------------------------
# 2. Subnets
#    Create apigee northbound VPC subnets for regions
# ------------------------------------------------------------------------------

# ----------
# Region 1
# ----------

resource "google_compute_subnetwork" "region1-subnet" {
  name = var.region1-subnet-name
  region = var.region1
  project = var.project_id
  network = google_compute_network.main_network.self_link
  ip_cidr_range = var.region1-subnet-iprange
  private_ip_google_access = true
}

resource "google_compute_subnetwork" "region1-proxy_only_subnet" {
  name = var.region1-proxy_only_subnet_name
  region = var.region1
  project = var.project_id
  network = google_compute_network.main_network.self_link
  ip_cidr_range = var.region1-pos-iprange
  purpose = "REGIONAL_MANAGED_PROXY"
  role = "ACTIVE"
}

# ----------
# Region 2
# ----------

resource "google_compute_subnetwork" "region2-subnet" {
  name = var.region2-subnet-name
  region = var.region2
  project = var.project_id
  network = google_compute_network.main_network.self_link
  ip_cidr_range = var.region2-subnet-iprange
  private_ip_google_access = true
}

resource "google_compute_subnetwork" "region2-proxy_only_subnet" {
  name = var.region2-proxy_only_subnet_name
  region = var.region2
  project = var.project_id
  network = google_compute_network.main_network.self_link
  ip_cidr_range = var.region2-pos-iprange
  purpose = "REGIONAL_MANAGED_PROXY"
  role = "ACTIVE"
}

# ----------
# Region 3
# ----------

resource "google_compute_subnetwork" "region3-subnet" {
  name = var.region3-subnet-name
  region = var.region3
  project = var.project_id
  network = google_compute_network.main_network.self_link
  ip_cidr_range = var.region3-subnet-iprange
  private_ip_google_access = true
}

resource "google_compute_subnetwork" "region3-proxy_only_subnet" {
  name = var.region3-proxy_only_subnet_name
  region = var.region3
  project = var.project_id
  network = google_compute_network.main_network.self_link
  ip_cidr_range = var.region3-pos-iprange
  purpose = "REGIONAL_MANAGED_PROXY"
  role = "ACTIVE"
}

# ----------
# Region 4
# ----------

resource "google_compute_subnetwork" "region4-subnet" {
  name = var.region4-subnet-name
  region = var.region4
  project = var.project_id
  network = google_compute_network.main_network.self_link
  ip_cidr_range = var.region4-subnet-iprange
  private_ip_google_access = true
}

resource "google_compute_subnetwork" "region4-proxy_only_subnet" {
  name = var.region4-proxy_only_subnet_name
  region = var.region4
  project = var.project_id
  network = google_compute_network.main_network.self_link
  ip_cidr_range = var.region4-pos-iprange
  purpose = "REGIONAL_MANAGED_PROXY"
  role = "ACTIVE"
}

# ------------------------------------------------------------------------------
# 3. PSC NETWORK ENDPOINT GROUP (NEG)
#    Points to your service via a Service Attachment.
# ------------------------------------------------------------------------------

# ----------
# Region 1
# ----------

resource "google_compute_region_network_endpoint_group" "region1-psc_neg" {
  project                  = var.project_id
  name                     = var.region1-psc-neg-name
  region                   = var.region1
  network                  = google_compute_network.main_network.self_link
  subnetwork               = google_compute_subnetwork.region1-subnet.self_link
  network_endpoint_type    = "PRIVATE_SERVICE_CONNECT"
  psc_target_service       = module.apigee-x-core.instance_service_attachments[var.region1]
  lifecycle {
    create_before_destroy = true
  }
}

# ----------
# Region 2
# ----------

resource "google_compute_region_network_endpoint_group" "region2-psc_neg" {
  project                  = var.project_id
  name                     = var.region2-psc-neg-name
  region                   = var.region2
  network                  = google_compute_network.main_network.self_link
  subnetwork               = google_compute_subnetwork.region2-subnet.self_link
  network_endpoint_type    = "PRIVATE_SERVICE_CONNECT"
  psc_target_service       = module.apigee-x-core.instance_service_attachments[var.region2]
  lifecycle {
    create_before_destroy = true
  }
}

# ----------
# Region 3
# ----------

resource "google_compute_region_network_endpoint_group" "region3-psc_neg" {
  project                  = var.project_id
  name                     = var.region3-psc-neg-name
  region                   = var.region3
  network                  = google_compute_network.main_network.self_link
  subnetwork               = google_compute_subnetwork.region3-subnet.self_link
  network_endpoint_type    = "PRIVATE_SERVICE_CONNECT"
  psc_target_service       = module.apigee-x-core.instance_service_attachments[var.region3]
  lifecycle {
    create_before_destroy = true
  }
}

# ----------
# Region 4
# ----------

resource "google_compute_region_network_endpoint_group" "region4-psc_neg" {
  project                  = var.project_id
  name                     = var.region4-psc-neg-name
  region                   = var.region4
  network                  = google_compute_network.main_network.self_link
  subnetwork               = google_compute_subnetwork.region4-subnet.self_link
  network_endpoint_type    = "PRIVATE_SERVICE_CONNECT"
  psc_target_service       = module.apigee-x-core.instance_service_attachments[var.region4]
  lifecycle {
    create_before_destroy = true
  }
}

# ------------------------------------------------------------------------------
# 4. REGIONAL INTERNAL APPLICATION LOAD BALANCER
#    Uses the PSC NEG as its backend. (Listens on var.internal_lb_port, typically HTTP)
# ------------------------------------------------------------------------------

## 4a. Regional Health Check for Internal LB's Backend Service
# resource "google_compute_region_health_check" "region1-ilb-hc" {
#   project = var.project_id
#   name    = var.region1-ilb-hc-name
#   region  = var.region1
#   http_health_check { # Assumes internal service responds to HTTP health checks on its serving port
#     port_specification = "USE_SERVING_PORT"
#   }
# }

# ----------
# Region 1
# ----------

## 4a. Regional Backend Service for Internal LB
resource "google_compute_region_backend_service" "region1-ilb-bes" {
  project                  = var.project_id
  name                     = var.region1-ilb-bes-name
  region                   = var.region1
  protocol                 = "HTTPS" # Internal communication protocol
  load_balancing_scheme    = "INTERNAL_MANAGED"
  log_config {
    enable = true
  }

  backend {
    group          = google_compute_region_network_endpoint_group.region1-psc_neg.id
    balancing_mode = "UTILIZATION"
  }
}

## 4b. Regional URL Map for Internal LB
resource "google_compute_region_url_map" "region1-ilb-urlmap" {
  project         = var.project_id
  name            = var.region1-ilb-urlmap-name
  region          = var.region1
  default_service = google_compute_region_backend_service.region1-ilb-bes.id
}

## 4c. Regional Target HTTP Proxy for Internal LB
resource "google_compute_region_target_http_proxy" "region1-ilb-targetproxy" {
  project = var.project_id
  name    = var.region1-ilb-targetproxy-name
  region  = var.region1
  url_map = google_compute_region_url_map.region1-ilb-urlmap.id
}

## 4d. Front end IP address for Internal LB
resource "google_compute_address" "region1-ilb-ip" {
    name         = var.region1-ilb-ip-name
    project      = var.project_id
    region       = var.region1
    subnetwork   = google_compute_subnetwork.region1-subnet.self_link
    address_type = "INTERNAL"  # or "INTERNAL" for internal load balancers
}


## 4e. Regional Forwarding Rule for Internal LB
resource "google_compute_forwarding_rule" "region1-ilb-forwardingrule" {
  project               = var.project_id
  name                  = var.region1-ilb-forwardingrule-name
  region                = var.region1
  ip_address            = google_compute_address.region1-ilb-ip.id
  ip_protocol           = "TCP"
  load_balancing_scheme = "INTERNAL_MANAGED"
  all_ports             = false
  port_range            = var.region1-ilb-port # Internal LB listens on this HTTP port
  target                = google_compute_region_target_http_proxy.region1-ilb-targetproxy.id
  network               = google_compute_network.main_network.self_link
  subnetwork            = google_compute_subnetwork.region1-subnet.self_link
  network_tier          = "PREMIUM"
  allow_global_access   = true
}

# ----------
# Region 2
# ----------

## 4a. Regional Backend Service for Internal LB
resource "google_compute_region_backend_service" "region2-ilb-bes" {
  project                  = var.project_id
  name                     = var.region2-ilb-bes-name
  region                   = var.region2
  protocol                 = "HTTPS" # Internal communication protocol
  load_balancing_scheme    = "INTERNAL_MANAGED"
  log_config {
    enable = true
  }

  backend {
    group          = google_compute_region_network_endpoint_group.region2-psc_neg.id
    balancing_mode = "UTILIZATION"
  }
}

## 4b. Regional URL Map for Internal LB
resource "google_compute_region_url_map" "region2-ilb-urlmap" {
  project         = var.project_id
  name            = var.region2-ilb-urlmap-name
  region          = var.region2
  default_service = google_compute_region_backend_service.region2-ilb-bes.id
}

## 4c. Regional Target HTTP Proxy for Internal LB
resource "google_compute_region_target_http_proxy" "region2-ilb-targetproxy" {
  project = var.project_id
  name    = var.region2-ilb-targetproxy-name
  region  = var.region2
  url_map = google_compute_region_url_map.region2-ilb-urlmap.id
}

## 4d. Front end IP address for Internal LB
resource "google_compute_address" "region2-ilb-ip" {
    name         = var.region2-ilb-ip-name
    project      = var.project_id
    region       = var.region2
    subnetwork   = google_compute_subnetwork.region2-subnet.self_link
    address_type = "INTERNAL"  # or "INTERNAL" for internal load balancers
}


## 4e. Regional Forwarding Rule for Internal LB
resource "google_compute_forwarding_rule" "region2-ilb-forwardingrule" {
  project               = var.project_id
  name                  = var.region2-ilb-forwardingrule-name
  region                = var.region2
  ip_address            = google_compute_address.region2-ilb-ip.id
  ip_protocol           = "TCP"
  load_balancing_scheme = "INTERNAL_MANAGED"
  all_ports             = false
  port_range            = var.region2-ilb-port # Internal LB listens on this HTTP port
  target                = google_compute_region_target_http_proxy.region2-ilb-targetproxy.id
  network               = google_compute_network.main_network.self_link
  subnetwork            = google_compute_subnetwork.region2-subnet.self_link
  network_tier          = "PREMIUM"
  allow_global_access   = true
}

# ----------
# Region 3
# ----------

## 4a. Regional Backend Service for Internal LB
resource "google_compute_region_backend_service" "region3-ilb-bes" {
  project                  = var.project_id
  name                     = var.region3-ilb-bes-name
  region                   = var.region3
  protocol                 = "HTTPS" # Internal communication protocol
  load_balancing_scheme    = "INTERNAL_MANAGED"
  log_config {
    enable = true
  }

  backend {
    group          = google_compute_region_network_endpoint_group.region3-psc_neg.id
    balancing_mode = "UTILIZATION"
  }
}

## 4b. Regional URL Map for Internal LB
resource "google_compute_region_url_map" "region3-ilb-urlmap" {
  project         = var.project_id
  name            = var.region3-ilb-urlmap-name
  region          = var.region3
  default_service = google_compute_region_backend_service.region3-ilb-bes.id
}

## 4c. Regional Target HTTP Proxy for Internal LB
resource "google_compute_region_target_http_proxy" "region3-ilb-targetproxy" {
  project = var.project_id
  name    = var.region3-ilb-targetproxy-name
  region  = var.region3
  url_map = google_compute_region_url_map.region3-ilb-urlmap.id
}

## 4d. Front end IP address for Internal LB
resource "google_compute_address" "region3-ilb-ip" {
    name         = var.region3-ilb-ip-name
    project      = var.project_id
    region       = var.region3
    subnetwork   = google_compute_subnetwork.region3-subnet.self_link
    address_type = "INTERNAL"  # or "INTERNAL" for internal load balancers
}


## 4e. Regional Forwarding Rule for Internal LB
resource "google_compute_forwarding_rule" "region3-ilb-forwardingrule" {
  project               = var.project_id
  name                  = var.region3-ilb-forwardingrule-name
  region                = var.region3
  ip_address            = google_compute_address.region3-ilb-ip.id
  ip_protocol           = "TCP"
  load_balancing_scheme = "INTERNAL_MANAGED"
  all_ports             = false
  port_range            = var.region3-ilb-port # Internal LB listens on this HTTP port
  target                = google_compute_region_target_http_proxy.region3-ilb-targetproxy.id
  network               = google_compute_network.main_network.self_link
  subnetwork            = google_compute_subnetwork.region3-subnet.self_link
  network_tier          = "PREMIUM"
  allow_global_access   = true
}

# ----------
# Region 4
# ----------

## 4a. Regional Backend Service for Internal LB
resource "google_compute_region_backend_service" "region4-ilb-bes" {
  project                  = var.project_id
  name                     = var.region4-ilb-bes-name
  region                   = var.region4
  protocol                 = "HTTPS" # Internal communication protocol
  load_balancing_scheme    = "INTERNAL_MANAGED"
  log_config {
    enable = true
  }

  backend {
    group          = google_compute_region_network_endpoint_group.region4-psc_neg.id
    balancing_mode = "UTILIZATION"
  }
}

## 4b. Regional URL Map for Internal LB
resource "google_compute_region_url_map" "region4-ilb-urlmap" {
  project         = var.project_id
  name            = var.region4-ilb-urlmap-name
  region          = var.region4
  default_service = google_compute_region_backend_service.region4-ilb-bes.id
}

## 4c. Regional Target HTTP Proxy for Internal LB
resource "google_compute_region_target_http_proxy" "region4-ilb-targetproxy" {
  project = var.project_id
  name    = var.region4-ilb-targetproxy-name
  region  = var.region4
  url_map = google_compute_region_url_map.region4-ilb-urlmap.id
}

## 4d. Front end IP address for Internal LB
resource "google_compute_address" "region4-ilb-ip" {
    name         = var.region4-ilb-ip-name
    project      = var.project_id
    region       = var.region4
    subnetwork   = google_compute_subnetwork.region4-subnet.self_link
    address_type = "INTERNAL"  # or "INTERNAL" for internal load balancers
}


## 4e. Regional Forwarding Rule for Internal LB
resource "google_compute_forwarding_rule" "region4-ilb-forwardingrule" {
  project               = var.project_id
  name                  = var.region4-ilb-forwardingrule-name
  region                = var.region4
  ip_address            = google_compute_address.region4-ilb-ip.id
  ip_protocol           = "TCP"
  load_balancing_scheme = "INTERNAL_MANAGED"
  all_ports             = false
  port_range            = var.region4-ilb-port # Internal LB listens on this HTTP port
  target                = google_compute_region_target_http_proxy.region4-ilb-targetproxy.id
  network               = google_compute_network.main_network.self_link
  subnetwork            = google_compute_subnetwork.region4-subnet.self_link
  network_tier          = "PREMIUM"
  allow_global_access   = true
}

# ------------------------------------------------------------------------------
# 5. HYBRID NETWORK ENDPOINT GROUP (NEG)
#    Packages the IP and port of the Regional Internal ALB.
# ------------------------------------------------------------------------------

# ----------
# Region 1
# ----------

## 5a. Network Endpoint Group for the Hybrid NEG
resource "google_compute_network_endpoint_group" "region1-hybrid-neg" {
  project                 = var.project_id
  name                    = var.region1-hybrid-neg-name
  zone                    = var.region1-zone1
  network                 = google_compute_network.main_network.self_link
  network_endpoint_type   = "NON_GCP_PRIVATE_IP_PORT"
  default_port            = var.region1-ilb-port # Points to the internal LB's HTTP port
}

## 5b. Network Endpoint for the Hybrid NEG
resource "google_compute_network_endpoint" "region1-hybrid-neg-endpoint" {
  project                 = var.project_id
  network_endpoint_group  = google_compute_network_endpoint_group.region1-hybrid-neg.self_link
  zone                    = var.region1-zone1
  ip_address              = google_compute_forwarding_rule.region1-ilb-forwardingrule.ip_address
  port                    = var.region1-ilb-port # Points to the internal LB's HTTP port
}

# ----------
# Region 2
# ----------

## 5a. Network Endpoint Group for the Hybrid NEG
resource "google_compute_network_endpoint_group" "region2-hybrid-neg" {
  project                 = var.project_id
  name                    = var.region2-hybrid-neg-name
  zone                    = var.region2-zone1
  network                 = google_compute_network.main_network.self_link
  network_endpoint_type   = "NON_GCP_PRIVATE_IP_PORT"
  default_port            = var.region2-ilb-port # Points to the internal LB's HTTP port
}

## 5b. Network Endpoint for the Hybrid NEG
resource "google_compute_network_endpoint" "region2-hybrid-neg-endpoint" {
  project                 = var.project_id
  network_endpoint_group  = google_compute_network_endpoint_group.region2-hybrid-neg.self_link
  zone                    = var.region2-zone1
  ip_address              = google_compute_forwarding_rule.region2-ilb-forwardingrule.ip_address
  port                    = var.region2-ilb-port # Points to the internal LB's HTTP port
}

# ----------
# Region 3
# ----------

## 5a. Network Endpoint Group for the Hybrid NEG
resource "google_compute_network_endpoint_group" "region3-hybrid-neg" {
  project                 = var.project_id
  name                    = var.region3-hybrid-neg-name
  zone                    = var.region3-zone1
  network                 = google_compute_network.main_network.self_link
  network_endpoint_type   = "NON_GCP_PRIVATE_IP_PORT"
  default_port            = var.region3-ilb-port # Points to the internal LB's HTTP port
}

## 5b. Network Endpoint for the Hybrid NEG
resource "google_compute_network_endpoint" "region3-hybrid-neg-endpoint" {
  project                 = var.project_id
  network_endpoint_group  = google_compute_network_endpoint_group.region3-hybrid-neg.self_link
  zone                    = var.region3-zone1
  ip_address              = google_compute_forwarding_rule.region3-ilb-forwardingrule.ip_address
  port                    = var.region3-ilb-port # Points to the internal LB's HTTP port
}

# ----------
# Region 4
# ----------

## 5a. Network Endpoint Group for the Hybrid NEG
resource "google_compute_network_endpoint_group" "region4-hybrid-neg" {
  project                 = var.project_id
  name                    = var.region4-hybrid-neg-name
  zone                    = var.region4-zone1
  network                 = google_compute_network.main_network.self_link
  network_endpoint_type   = "NON_GCP_PRIVATE_IP_PORT"
  default_port            = var.region4-ilb-port # Points to the internal LB's HTTP port
}

## 5b. Network Endpoint for the Hybrid NEG
resource "google_compute_network_endpoint" "region4-hybrid-neg-endpoint" {
  project                 = var.project_id
  network_endpoint_group  = google_compute_network_endpoint_group.region4-hybrid-neg.self_link
  zone                    = var.region4-zone1
  ip_address              = google_compute_forwarding_rule.region4-ilb-forwardingrule.ip_address
  port                    = var.region4-ilb-port # Points to the internal LB's HTTP port
}

# ------------------------------------------------------------------------------
# 6. EXTERNAL HTTPS APPLICATION LOAD BALANCER
#    Uses the Hybrid NEG as its backend. Routes external HTTPS traffic.
# ------------------------------------------------------------------------------


## 6b. Google-managed SSL Certificate for External LB
# This resource is created only if domain names are provided.
# DNS A/AAAA records for these domains must point to apigee-xlb-ip.address for provisioning.
resource "google_compute_managed_ssl_certificate" "apigee-xlb-ssl-certificate" {
  count = 1

  project = var.project_id
  name    = var.apigee-xlb-ssl-certificate-name
  managed {
    domains = ["${google_compute_global_address.apigee-xlb-ip.address}.nip.io"]
  }
}

## 6c. Global Health Check for External LB's Backend Service
# Health check still targets the internal LB's HTTP port and protocol.
resource "google_compute_health_check" "apigee-xlb-hc-tcp" {
  project = var.project_id
  name    = var.apigee-xlb-hc-tcp-name
  tcp_health_check {
    port = var.region1-ilb-port
  }
  timeout_sec         = 5
  check_interval_sec  = 5
  healthy_threshold   = 2
  unhealthy_threshold = 2
  log_config {
    enable = true
  }
}

## 6d. Global Backend Service for External LB
# This backend service still expects HTTP communication with the Hybrid NEG (internal LB).
resource "google_compute_backend_service" "apigee-xlb-bes" {
  project                  = var.project_id
  name                     = var.apigee-xlb-bes-name
  protocol                 = "HTTP" # Protocol to Hybrid NEG; SSL is terminated at the LB
  port_name                = "http" # Named port for backend service
  load_balancing_scheme    = "EXTERNAL_MANAGED"
  health_checks            = [google_compute_health_check.apigee-xlb-hc-tcp.id]
  log_config {
    enable = true
  }

  backend {
    group                   = google_compute_network_endpoint_group.region1-hybrid-neg.id
    balancing_mode          = "RATE"
    max_rate_per_endpoint   = 1000
    preference              = "PREFERRED"
  }
  backend {
    group                   = google_compute_network_endpoint_group.region2-hybrid-neg.id
    balancing_mode          = "RATE"
    max_rate_per_endpoint   = 1000
  }
  backend {
    group                   = google_compute_network_endpoint_group.region3-hybrid-neg.id
    balancing_mode          = "RATE"
    max_rate_per_endpoint   = 1000
  }
  backend {
    group                   = google_compute_network_endpoint_group.region4-hybrid-neg.id
    balancing_mode          = "RATE"
    max_rate_per_endpoint   = 1000
  }
}

## 6e. Global URL Map for External LB
resource "google_compute_url_map" "apigee-xlb-urlmap" {
  project         = var.project_id
  name            = var.apigee-xlb-urlmap-name
  default_service = google_compute_backend_service.apigee-xlb-bes.id
}

## 6f. Global Target HTTPS Proxy for External LB
# This resource is created only if an SSL certificate is available.
resource "google_compute_target_https_proxy" "apigee-xlb-targetproxy" {
  count = 1

  project          = var.project_id
  name             = var.apigee-xlb-https-targetproxy-name
  url_map          = google_compute_url_map.apigee-xlb-urlmap.id
  ssl_certificates = [google_compute_managed_ssl_certificate.apigee-xlb-ssl-certificate[0].self_link]
}

## 6g. Global Forwarding Rule for External LB
# This resource is created only if a TargetHTTPSProxy is available.
resource "google_compute_global_forwarding_rule" "external_lb_forwarding_rule" {
  count = 1

  project               = var.project_id
  name                  = var.apigee-xlb-https-fwd-rule-name
  ip_protocol           = "TCP"
  load_balancing_scheme = "EXTERNAL_MANAGED"
  port_range            = var.apigee-xlb-port # Port 443 by default
  target = google_compute_target_https_proxy.apigee-xlb-targetproxy[0].id # Points to HTTPS proxy
  ip_address            = google_compute_global_address.apigee-xlb-ip.address
}

# ------------------------------------------------------------------------------
# 5. Firewall setup
#    Set up firewall rules for XLB -> Hybrid NEG -> ILB -> PSC NEG
# ------------------------------------------------------------------------------

resource "google_compute_firewall" "apigee-vpc-fw-xlb-https-ingress" {
  name  = var.apigee-vpc-fw-xlb-https-ingress-name
  network = google_compute_network.main_network.self_link
  direction = "INGRESS"
  description = "VPC firewall rule that allows Internet -> HTTPS into XLB"
  allow {
    protocol = "tcp"
    ports    = [443]
  }
  source_ranges = ["0.0.0.0/0"]
  destination_ranges = ["${google_compute_global_address.apigee-xlb-ip.address}/32"]
  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "apigee-vpc-fw-hneg-http-ingress" {
  name  = var.apigee-vpc-fw-hneg-http-ingress-name
  network = google_compute_network.main_network.self_link
  direction = "INGRESS"
  description = "VPC firewall rule that allows XLB -> HTTP into Hybrid NEG -> Regional ILB"
  allow {
    protocol = "tcp"
    ports    = [80,443]
  }
  source_ranges = ["${google_compute_global_address.apigee-xlb-ip.address}/32"]
  destination_ranges = ["${google_compute_subnetwork.region1-subnet.ip_cidr_range}", "${google_compute_subnetwork.region2-subnet.ip_cidr_range}", "${google_compute_subnetwork.region3-subnet.ip_cidr_range}", "${google_compute_subnetwork.region4-subnet.ip_cidr_range}"]
  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "apigee-vpc-fw-psc-https-egress" {
  name  = var.apigee-vpc-fw-psc-https-egress-name
  network = google_compute_network.main_network.self_link
  direction = "EGRESS"
  description = "VPC firewall rule that allows Regional ILB -> HTTPS into PSC NEG -> PSC Service Attachment for Apigee Instance"
  allow {
    protocol = "tcp"
    ports    = [443]
  }
  source_ranges = ["${google_compute_address.region1-ilb-ip.address}/32", "${google_compute_address.region2-ilb-ip.address}/32", "${google_compute_address.region3-ilb-ip.address}/32", "${google_compute_address.region4-ilb-ip.address}/32"]
  destination_ranges = ["10.0.0.0/8"]
  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

resource "google_compute_firewall" "apigee-vpc-fw-health-check-ingress" {
  name  = var.apigee-vpc-fw-allow-health-check-ingress-name
  network = google_compute_network.main_network.self_link
  direction = "INGRESS"
  description = "VPC firewall rule that allows IPV4 based GCP health check probes to reach load balancers"
  allow {
    protocol = "tcp"
  }
  source_ranges = ["35.191.0.0/16", "130.211.0.0/22", "209.85.152.0/22", "209.85.204.0/22"]
  destination_ranges = ["${google_compute_global_address.apigee-xlb-ip.address}/32", "${google_compute_address.region1-ilb-ip.address}/32", "${google_compute_address.region2-ilb-ip.address}/32", "${google_compute_address.region3-ilb-ip.address}/32", "${google_compute_address.region4-ilb-ip.address}/32"]
  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
}

