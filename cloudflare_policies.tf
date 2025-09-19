
terraform {
  required_providers {
    cloudflare = {
      source = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
}

provider "cloudflare" {
  # Configuration will be taken from environment variables:
  # CLOUDFLARE_API_TOKEN or CLOUDFLARE_EMAIL + CLOUDFLARE_API_KEY
}

variable "account_id" {
  description = "Cloudflare account ID"
  type        = string
}

variable "team_name" {
  description = "Cloudflare Zero Trust team name"
  type        = string
}


resource "cloudflare_access_policy" "tls_policy_1" {
  account_id     = var.account_id
  name          = "Block Invalid SSL Certificates"
  precedence    = 100
  decision      = "block"
  
  include {
    # Configure your include conditions based on policy requirements
    everyone = true
  }
  
  # Policy conditions would need to be implemented based on 
  # Cloudflare's current HTTP policy structure
  # This is a template that needs customization
}


resource "cloudflare_access_policy" "tls_policy_2" {
  account_id     = var.account_id
  name          = "Warn on Weak SSL/TLS"
  precedence    = 200
  decision      = "allow"
  
  include {
    # Configure your include conditions based on policy requirements
    everyone = true
  }
  
  # Policy conditions would need to be implemented based on 
  # Cloudflare's current HTTP policy structure
  # This is a template that needs customization
}


resource "cloudflare_access_policy" "tls_policy_3" {
  account_id     = var.account_id
  name          = "Block Untrusted Certificate Authorities"
  precedence    = 150
  decision      = "block"
  
  include {
    # Configure your include conditions based on policy requirements
    everyone = false
  }
  
  # Policy conditions would need to be implemented based on 
  # Cloudflare's current HTTP policy structure
  # This is a template that needs customization
}


resource "cloudflare_access_policy" "tls_policy_4" {
  account_id     = var.account_id
  name          = "Require Certificate Transparency"
  precedence    = 175
  decision      = "block"
  
  include {
    # Configure your include conditions based on policy requirements
    everyone = true
  }
  
  # Policy conditions would need to be implemented based on 
  # Cloudflare's current HTTP policy structure
  # This is a template that needs customization
}


resource "cloudflare_access_policy" "tls_policy_5" {
  account_id     = var.account_id
  name          = "Enforce HSTS for Critical Sites"
  precedence    = 300
  decision      = "block"
  
  include {
    # Configure your include conditions based on policy requirements
    everyone = true
  }
  
  # Policy conditions would need to be implemented based on 
  # Cloudflare's current HTTP policy structure
  # This is a template that needs customization
}


resource "cloudflare_access_policy" "tls_policy_6" {
  account_id     = var.account_id
  name          = "Block Short Certificate Validity"
  precedence    = 250
  decision      = "allow"
  
  include {
    # Configure your include conditions based on policy requirements
    everyone = true
  }
  
  # Policy conditions would need to be implemented based on 
  # Cloudflare's current HTTP policy structure
  # This is a template that needs customization
}


resource "cloudflare_access_policy" "tls_policy_7" {
  account_id     = var.account_id
  name          = "Enforce Strong Key Sizes"
  precedence    = 180
  decision      = "block"
  
  include {
    # Configure your include conditions based on policy requirements
    everyone = true
  }
  
  # Policy conditions would need to be implemented based on 
  # Cloudflare's current HTTP policy structure
  # This is a template that needs customization
}


resource "cloudflare_access_policy" "tls_policy_8" {
  account_id     = var.account_id
  name          = "Block Mixed Content"
  precedence    = 320
  decision      = "block"
  
  include {
    # Configure your include conditions based on policy requirements
    everyone = true
  }
  
  # Policy conditions would need to be implemented based on 
  # Cloudflare's current HTTP policy structure
  # This is a template that needs customization
}


resource "cloudflare_access_policy" "tls_policy_9" {
  account_id     = var.account_id
  name          = "PCI DSS Certificate Requirements"
  precedence    = 400
  decision      = "block"
  
  include {
    # Configure your include conditions based on policy requirements
    everyone = false
  }
  
  # Policy conditions would need to be implemented based on 
  # Cloudflare's current HTTP policy structure
  # This is a template that needs customization
}


resource "cloudflare_access_policy" "tls_policy_10" {
  account_id     = var.account_id
  name          = "HIPAA Compliance Certificate Validation"
  precedence    = 450
  decision      = "block"
  
  include {
    # Configure your include conditions based on policy requirements
    everyone = false
  }
  
  # Policy conditions would need to be implemented based on 
  # Cloudflare's current HTTP policy structure
  # This is a template that needs customization
}


resource "cloudflare_access_policy" "tls_policy_11" {
  account_id     = var.account_id
  name          = "Government Site Certificate Validation"
  precedence    = 475
  decision      = "block"
  
  include {
    # Configure your include conditions based on policy requirements
    everyone = true
  }
  
  # Policy conditions would need to be implemented based on 
  # Cloudflare's current HTTP policy structure
  # This is a template that needs customization
}


resource "cloudflare_access_policy" "tls_policy_12" {
  account_id     = var.account_id
  name          = "Monitor Certificate Changes"
  precedence    = 500
  decision      = "allow"
  
  include {
    # Configure your include conditions based on policy requirements
    everyone = true
  }
  
  # Policy conditions would need to be implemented based on 
  # Cloudflare's current HTTP policy structure
  # This is a template that needs customization
}


resource "cloudflare_access_policy" "tls_policy_13" {
  account_id     = var.account_id
  name          = "Track Certificate Authority Usage"
  precedence    = 550
  decision      = "allow"
  
  include {
    # Configure your include conditions based on policy requirements
    everyone = true
  }
  
  # Policy conditions would need to be implemented based on 
  # Cloudflare's current HTTP policy structure
  # This is a template that needs customization
}


resource "cloudflare_access_policy" "tls_policy_14" {
  account_id     = var.account_id
  name          = "Alert on New Certificate Authorities"
  precedence    = 525
  decision      = "allow"
  
  include {
    # Configure your include conditions based on policy requirements
    everyone = true
  }
  
  # Policy conditions would need to be implemented based on 
  # Cloudflare's current HTTP policy structure
  # This is a template that needs customization
}
