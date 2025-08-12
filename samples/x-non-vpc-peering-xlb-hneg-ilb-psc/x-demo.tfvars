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

ax_region = "us-east1"

apigee_instances = {
  use1-inst = {
    region       = "us-east1"
    environments = ["dev-env", "test-env"]
  }
  usw1-inst = {
    region       = "us-west1"
    environments = ["dev-env", "test-env"]
  }
  use4-inst = {
    region       = "us-east4"
    environments = ["dev-env", "test-env"]
  }
  use5-inst = {
    region       = "us-east5"
    environments = ["dev-env", "test-env"]
  }
}

apigee_environments = {
  dev-env = {
    display_name = "Dev-Env"
    description  = "Dev environment created by apigee/terraform-modules"
    node_config  = null
    iam          = null
    envgroups    = ["test-env-grp"]
    type         = "COMPREHENSIVE"
  }
  test-env = {
    display_name = "Test-Env"
    description  = "Test environment created by apigee/terraform-modules"
    node_config  = null
    iam          = null
    envgroups    = ["test-env-grp"]
    type         = "COMPREHENSIVE"
  }
}

apigee_envgroups = {
  test-env-grp = {
    hostnames = []
  }
}

network_name = "apigee-nb-nw"

# Region 1 Variables

region1 = "us-east1"

region1-zone1 = "us-east1-b"

region1-subnet-name = "apigee-nb-nw-subnet-us-east1"

region1-subnet-iprange = "10.1.0.0/23"

region1-pos-iprange = "10.3.0.0/23"

region1-proxy_only_subnet_name = "apigee-nb-nw-us-east1-pos"

region1-psc-neg-name = "apigee-us-east1-psc-neg"

region1-apigee-psc_target_service_attachment_uri = "projects/p54d5feba6873adbap-tp/regions/us-east1/serviceAttachments/apigee-us-east1-giy9"

region1-ilb-hc-name = "apigee-us-east1-ilb-hc"

region1-ilb-bes-name = "apigee-us-east1-ilb-bes"

region1-ilb-port = 80

region1-ilb-urlmap-name = "apigee-us-east1-ilb-urlmap"

region1-ilb-targetproxy-name = "apigee-us-east1-ilb-targetproxy"

region1-ilb-ip-name = "apigee-us-east1-ilb-ip"

region1-ilb-forwardingrule-name = "apigee-us-east1-ilb-forwardingrule"

region1-hybrid-neg-name = "apigee-us-east1-hybrid-neg"

# Region 2 Variables

region2 = "us-west1"

region2-zone1 = "us-west1-b"

region2-subnet-name = "apigee-nb-nw-subnet-us-west1"

region2-subnet-iprange = "10.2.0.0/23"

region2-pos-iprange = "10.4.0.0/23"

region2-proxy_only_subnet_name = "apigee-nb-nw-us-west1-pos"

region2-psc-neg-name = "apigee-us-west1-psc-neg"

region2-apigee-psc_target_service_attachment_uri = "projects/p54d5feba6873adbap-tp/regions/us-west1/serviceAttachments/apigee-us-west1-eaxq"

region2-ilb-hc-name = "apigee-us-west1-ilb-hc"

region2-ilb-bes-name = "apigee-us-west1-ilb-bes"

region2-ilb-port = 80

region2-ilb-urlmap-name = "apigee-us-west1-ilb-urlmap"

region2-ilb-targetproxy-name = "apigee-us-west1-ilb-targetproxy"

region2-ilb-ip-name = "apigee-us-west1-ilb-ip"

region2-ilb-forwardingrule-name = "apigee-us-west1-ilb-forwardingrule"

region2-hybrid-neg-name = "apigee-us-west1-hybrid-neg"

# Region 3 Variables

region3 = "us-east4"

region3-zone1 = "us-east4-a"

region3-subnet-name = "apigee-nb-nw-subnet-us-east4"

region3-subnet-iprange = "10.5.0.0/23"

region3-pos-iprange = "10.6.0.0/23"

region3-proxy_only_subnet_name = "apigee-nb-nw-us-east4-pos"

region3-psc-neg-name = "apigee-us-east4-psc-neg"

region3-apigee-psc_target_service_attachment_uri = "projects/p54d5feba6873adbap-tp/regions/us-west1/serviceAttachments/apigee-us-west1-eaxq"

region3-ilb-hc-name = "apigee-us-east4-ilb-hc"

region3-ilb-bes-name = "apigee-us-east4-ilb-bes"

region3-ilb-port = 80

region3-ilb-urlmap-name = "apigee-us-east4-ilb-urlmap"

region3-ilb-targetproxy-name = "apigee-us-east4-ilb-targetproxy"

region3-ilb-ip-name = "apigee-us-east4-ilb-ip"

region3-ilb-forwardingrule-name = "apigee-us-east4-ilb-forwardingrule"

region3-hybrid-neg-name = "apigee-us-east4-hybrid-neg"

# Region 4 Variables

region4 = "us-east5"

region4-zone1 = "us-east5-b"

region4-subnet-name = "apigee-nb-nw-subnet-us-east5"

region4-subnet-iprange = "10.7.0.0/23"

region4-pos-iprange = "10.8.0.0/23"

region4-proxy_only_subnet_name = "apigee-nb-nw-us-east5-pos"

region4-psc-neg-name = "apigee-us-east5-psc-neg"

region4-apigee-psc_target_service_attachment_uri = "projects/p54d5feba6873adbap-tp/regions/us-west1/serviceAttachments/apigee-us-west1-eaxq"

region4-ilb-hc-name = "apigee-us-east5-ilb-hc"

region4-ilb-bes-name = "apigee-us-east5-ilb-bes"

region4-ilb-port = 80

region4-ilb-urlmap-name = "apigee-us-east5-ilb-urlmap"

region4-ilb-targetproxy-name = "apigee-us-east5-ilb-targetproxy"

region4-ilb-ip-name = "apigee-us-east5-ilb-ip"

region4-ilb-forwardingrule-name = "apigee-us-east5-ilb-forwardingrule"

region4-hybrid-neg-name = "apigee-us-east5-hybrid-neg"

# XLB Variables

apigee-xlb-port = 443

apigee-xlb-ip-name = "apigee-xlb-ip"

apigee-xlb-ssl-certificate-name = "apigee-xlb-ssl-certificate"

apigee-xlb-hc-tcp-name = "apigee-xlb-hc-tcp"

apigee-xlb-bes-name = "apigee-xlb-bes"

apigee-xlb-urlmap-name = "apigee-xlb-urlmap"

apigee-xlb-https-targetproxy-name = "apigee-xlb-https-targetproxy"

apigee-xlb-https-fwd-rule-name = "apigee-xlb-https-fwd-rule"

apigee_billing_type = "PAYG"

apigee-vpc-fw-xlb-https-ingress-name = "apigee-vpc-fw-xlb-https-ingress"

apigee-vpc-fw-hneg-http-ingress-name = "apigee-vpc-fw-hneg-http-ingress"

apigee-vpc-fw-psc-https-egress-name = "apigee-vpc-fw-psc-https-egress"

apigee-vpc-fw-allow-health-check-ingress-name = "apigee-vpc-fw-allow-health-check-ingress"

apigee-vpc-fw-allow-health-check-ipv6-ingress-name = "apigee-vpc-fw-allow-health-check-ipv6-ingress"

# psc_ingress_network = "psc-ingress-vpc"

# psc_ingress_subnets = [
#   {
#     name               = "apigee-psc-usw1"
#     ip_cidr_range      = "10.100.0.0/24"
#     region             = "us-west1"
#     secondary_ip_range = null
#   }
# ]