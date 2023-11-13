# terraform-provider-keycloakwebhook

Provider for keycloak webhooks https://github.com/p2-inc/keycloak-events. Provider configuration fully compatibly with
keycloak provider https://github.com/mrparkers/terraform-provider-keycloak

## Docs

All documentation for this provider can now be found on the Terraform
Registry: https://registry.terraform.io/providers/2tvenom/keycloakwebhook/latest/docs

## Installation

This provider can be installed automatically using Terraform >=0.13 by using the `terraform` configuration block:

```hcl
terraform {
  required_providers {
    keycloakwebhook = {
      source  = "2tvenom/keycloakwebhook"
      version = ">= 0.1.0"
    }
  }
}
```