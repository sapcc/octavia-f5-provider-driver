# provider
terraform {
  required_providers {
    openstack = {
      source  = "terraform-providers/openstack"
    }
  }
}

provider "openstack" {
  version = ">= 1.19.0"

  user_name        = var.os_username
  user_domain_name = var.os_user_domain
  tenant_name      = var.os_project
  domain_name      = var.os_domain
  password         = var.os_password
  auth_url         = var.os_auth_url
  region           = var.os_region
  use_octavia      = "true"
}

locals {
  count = 100
}

resource "openstack_lb_loadbalancer_v2" "terraform" {
  count = local.count
  name = "terraform-generated-loadbalancer-${count.index}"
  vip_network_id = var.priv_network
}

resource "openstack_lb_listener_v2" "terraform" {
  count = local.count
  name = "terraform-generated-listener-${count.index}"
  protocol        = "HTTP"
  protocol_port   = 8080
  loadbalancer_id = openstack_lb_loadbalancer_v2.terraform[count.index].id

  insert_headers = {
    X-Forwarded-For = "true"
  }  
}

resource "openstack_lb_pool_v2" "terraform" {
  name = "terraform-generated-pool-${count.index}"
  count = local.count
  protocol    = "HTTP"
  lb_method   = "ROUND_ROBIN"
  listener_id = openstack_lb_listener_v2.terraform[count.index].id

  persistence {
    type        = "APP_COOKIE"
    cookie_name = "testCookie"
  } 
}

resource "openstack_lb_members_v2" "terraform" {
  pool_id = openstack_lb_pool_v2.terraform[count.index].id
  count = local.count

  member {
    address       = "192.168.199.23"
    protocol_port = 8080
  }

  member {
    address       = "192.168.199.24"
    protocol_port = 8080
  }
}

resource "openstack_lb_monitor_v2" "terraform" {
  count = local.count
  pool_id     = openstack_lb_pool_v2.terraform[count.index].id
  type        = "PING"
  delay       = 20
  timeout     = 10
  max_retries = 5
}

resource "openstack_lb_l7policy_v2" "terraform" {
  count = local.count
  name = "terraform-generated-l7policy-${count.index}"
  action           = "REJECT"
  description      = "test l7 policy"
  position         = 1
  listener_id      = openstack_lb_listener_v2.terraform[count.index].id
}

resource "openstack_lb_l7rule_v2" "terraform" {
  count = local.count
  l7policy_id  = openstack_lb_l7policy_v2.terraform[count.index].id
  type         = "PATH"
  compare_type = "EQUAL_TO"
  value        = "/api"
}

