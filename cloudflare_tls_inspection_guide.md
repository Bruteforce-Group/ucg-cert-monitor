# Cloudflare Zero Trust TLS Inspection Implementation Guide

## Overview
This guide will help you implement TLS certificate inspection using your existing Cloudflare Gateway setup (`CF-ZTG` - `1skb01k34.cloudflare-gateway.com`).

## Prerequisites
- Cloudflare Zero Trust account with Gateway enabled
- Admin access to Cloudflare Zero Trust dashboard
- Root/admin access to client devices for certificate installation

## Step 1: Configure TLS Inspection Policies in Cloudflare Zero Trust Dashboard

### 1.1 Access the Dashboard
1. Go to https://one.dash.cloudflare.com/
2. Navigate to **Gateway** → **Policies** → **HTTP**

### 1.2 Enable TLS Inspection
1. Go to **Settings** → **Network** → **TLS Decryption**
2. Enable **TLS Decryption** for your team
3. Configure inspection scope:
   - **All traffic** (comprehensive but resource intensive)
   - **Specific categories** (recommended for performance)
   - **Custom domains** (targeted approach)

### 1.3 Create HTTP/HTTPS Policies
Example policies to implement:

#### Policy 1: Block Invalid Certificates
```yaml
Name: Block Invalid SSL Certificates
Type: HTTP
Action: Block
Conditions:
  - SSL Certificate Status equals "Invalid"
  - SSL Certificate Status equals "Expired"
  - SSL Certificate Status equals "Self-Signed"
```

#### Policy 2: Warn on Weak Encryption
```yaml
Name: Warn Weak Encryption
Type: HTTP  
Action: Allow with warning
Conditions:
  - SSL Cipher Suite contains "RC4"
  - SSL Cipher Suite contains "DES"
  - SSL Version equals "SSLv2"
  - SSL Version equals "SSLv3"
```

#### Policy 3: Block Untrusted CAs
```yaml
Name: Block Untrusted Certificate Authorities
Type: HTTP
Action: Block
Conditions:
  - SSL Certificate Issuer not in "Trusted CA List"
```

### 1.4 Certificate Validation Rules
Configure these validation checks:
- **Certificate Transparency**: Require CT log presence
- **OCSP Stapling**: Verify revocation status
- **HSTS Compliance**: Enforce strict transport security
- **Certificate Pinning**: For critical internal services

## Step 2: Deploy Root CA Certificate to All Client Devices

### 2.1 Download Cloudflare Root CA
The root certificate will be available at:
- **Download URL**: `https://developers.cloudflare.com/cloudflare-one/static/documentation/connections/Cloudflare_CA.crt`
- **Certificate Type**: X.509 PEM format

### 2.2 macOS Installation
```bash
# Download certificate
curl -o Cloudflare_CA.crt https://developers.cloudflare.com/cloudflare-one/static/documentation/connections/Cloudflare_CA.crt

# Install certificate
sudo security add-trusted-cert -d -r trustRoot -k /System/Library/Keychains/SystemRootCertificates.keychain Cloudflare_CA.crt

# Verify installation
security find-certificate -c "Cloudflare" -p /System/Library/Keychains/SystemRootCertificates.keychain
```

### 2.3 Windows Installation
```powershell
# Download and install via PowerShell
Invoke-WebRequest -Uri "https://developers.cloudflare.com/cloudflare-one/static/documentation/connections/Cloudflare_CA.crt" -OutFile "Cloudflare_CA.crt"
Import-Certificate -FilePath "Cloudflare_CA.crt" -CertStoreLocation "Cert:\LocalMachine\Root"
```

### 2.4 Linux Installation
```bash
# Download certificate
wget https://developers.cloudflare.com/cloudflare-one/static/documentation/connections/Cloudflare_CA.crt

# Install for system-wide trust
sudo cp Cloudflare_CA.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

### 2.5 Mobile Device Configuration
- **iOS**: Use Configuration Profile or MDM
- **Android**: Install via Settings → Security → Install from storage

## Step 3: Set up HTTP/HTTPS Policies for Certificate Validation

### 3.1 Advanced Certificate Policies

#### Certificate Transparency Policy
```yaml
Name: Require Certificate Transparency
Type: HTTP
Action: Block
Conditions:
  - SSL Certificate CT Status equals "Not Present"
  - Domain Category equals "Business Critical"
```

#### Extended Validation Policy
```yaml
Name: Require EV Certificates for Financial Sites
Type: HTTP
Action: Block
Conditions:
  - SSL Certificate Type not equals "Extended Validation"
  - Domain Category equals "Financial Services"
```

#### Certificate Age Policy
```yaml
Name: Block Old Certificates
Type: HTTP
Action: Block
Conditions:
  - SSL Certificate Days Until Expiry less than 30
  - Destination equals "Critical Internal Services"
```

### 3.2 Custom Certificate Validation
```yaml
Name: Corporate Certificate Requirements
Type: HTTP
Action: Block
Conditions:
  - SSL Certificate Issuer not in ["DigiCert", "Let's Encrypt", "Internal CA"]
  - Domain equals "*.company.com"
```

## Step 4: Enable Gateway Certificate Inspection

### 4.1 Configure Inspection Settings
1. **Gateway** → **Settings** → **Network**
2. **TLS Decryption** → **Advanced Settings**
3. Configure:
   - **Inspection Mode**: Full inspection vs. metadata only
   - **Certificate Caching**: Enable for performance
   - **Bypass Lists**: Exclude sensitive services (banking, healthcare)

### 4.2 Logging Configuration
```yaml
Log Settings:
  - Certificate validation failures
  - Policy violations
  - TLS handshake failures
  - Cipher suite downgrades
```

### 4.3 Performance Optimization
- **Regional Processing**: Use closest CF edge locations
- **Selective Inspection**: Target high-risk categories
- **Cache Validation Results**: Reduce redundant checks

## Step 5: Testing and Validation

### 5.1 Test Certificate Validation
```bash
# Test blocked invalid certificate
curl -v https://expired.badssl.com/

# Test weak cipher detection  
curl -v --ciphers "RC4-SHA" https://rc4.badssl.com/

# Test self-signed certificate
curl -v https://self-signed.badssl.com/
```

### 5.2 Validate Policy Enforcement
1. Navigate to blocked sites
2. Check Gateway logs for policy triggers
3. Verify certificate details in inspection logs

## Step 6: Monitoring and Alerting

### 6.1 Dashboard Monitoring
- **Gateway** → **Analytics** → **HTTP**
- Monitor blocked requests by certificate issues
- Track policy violation trends

### 6.2 Integration with Existing Monitoring
Update your `ucg-cert-monitor` to include:
- Cloudflare Gateway API for TLS inspection logs
- Certificate policy violation alerts
- Automated certificate renewal warnings

## Troubleshooting

### Common Issues
1. **Certificate Trust Issues**: Ensure root CA is properly installed
2. **Performance Impact**: Fine-tune inspection scope
3. **App Compatibility**: Configure bypasses for certificate pinning apps
4. **False Positives**: Adjust policy thresholds

### Bypass Configuration
For apps that use certificate pinning:
```yaml
Bypass Policy:
  Name: Certificate Pinning Apps
  Type: HTTP
  Action: Bypass
  Conditions:
    - Application equals "Mobile Banking Apps"
    - Application equals "Internal Corporate Apps"
```

## Next Steps
1. Start with DNS-level policies (already active)
2. Gradually enable TLS inspection for test users
3. Monitor performance and adjust policies
4. Roll out to full organization
5. Integrate with certificate lifecycle management

## Security Benefits
Once implemented, you'll gain:
- **Real-time certificate validation**
- **Weak encryption detection**
- **Malicious certificate blocking**
- **Certificate transparency enforcement**
- **Comprehensive TLS visibility**

This enhances your existing UCG certificate monitoring with active protection and policy enforcement.
