# Cloudflare Gateway HTTPS Decryption Setup Guide

## 🎯 Objective
Configure your Mac to trust the Cloudflare Gateway CA certificate for HTTPS decryption, enabling Gateway to inspect encrypted traffic for security threats.

## ✅ Certificate Installation Status
- **Certificate File**: `~/Downloads/certificate (1).pem`
- **Certificate Type**: Gateway CA - Cloudflare Managed G2  
- **Account ID**: 0b0ee2b5eaf1fb8a2612e40ab6488052 ✅
- **Validity**: 2025-2030 (5 years) ✅
- **Installation**: Added to user keychain ✅
- **Trust Configuration**: **MANUAL STEP REQUIRED** ⚠️

## 🔧 Manual Trust Configuration Required

### Step 1: Open Keychain Access
Keychain Access should already be open. If not:
```bash
open -a "Keychain Access"
```

### Step 2: Locate the Certificate
1. In Keychain Access, make sure you're viewing "login" keychain
2. Search for: `Gateway CA - Cloudflare`
3. You should see the certificate with Cloudflare branding

### Step 3: Configure Trust Settings
1. **Double-click** the "Gateway CA - Cloudflare Managed G2" certificate
2. **Expand** the "Trust" section (click the triangle)
3. Find "When using this certificate:" dropdown
4. **Change from "Use System Defaults" to "Always Trust"**
5. **Close** the certificate dialog
6. **Enter your Mac password** when prompted
7. The certificate should now show a blue "+" icon indicating trust

### Step 4: Verify Configuration
Run this command to verify trust:
```bash
security verify-cert -c ~/Downloads/certificate\ \(1\).pem
```

## 🧪 Testing HTTPS Decryption

After configuring trust, test if Gateway is intercepting HTTPS:

```bash
# Test if Gateway certificate appears in HTTPS connections
openssl s_client -connect google.com:443 -servername google.com < /dev/null 2>/dev/null | openssl x509 -noout -issuer

# Should show Gateway CA as issuer if decryption is active
```

## 📊 Gateway HTTPS Decryption Rules

Your Gateway has an "HTTP Off" rule for Microsoft 365:
- **Rule**: `HTTP Off: Microsoft 365 Decryption Bypass`
- **Purpose**: Prevents decryption of Microsoft 365 traffic (compliance)
- **Status**: Active (precedence 210)

## 🛡️ What HTTPS Decryption Enables

Once configured, Gateway can:
- ✅ **Inspect encrypted traffic** for malware and threats
- ✅ **Apply HTTP block rules** to HTTPS sites  
- ✅ **Detect encrypted malware downloads**
- ✅ **Block HTTPS-based attacks** (SQL injection, XSS, etc.)
- ✅ **Provide detailed traffic analytics**

## ⚠️ Privacy Considerations

**HTTPS Decryption means Gateway can see:**
- All website content you visit
- Form data and login information  
- Downloaded files and uploads
- API requests and responses

**Microsoft 365 Exception:**
- M365 traffic bypassed (compliance requirement)
- Email, OneDrive, Teams remain private
- Business applications protected

## 🔍 Verification Commands

After trust configuration:

```bash
# Check certificate trust status
security find-certificate -c "Gateway CA - Cloudflare" -p ~/Library/Keychains/login.keychain-db | openssl x509 -noout -subject

# Test HTTPS connection with Gateway
curl -I https://google.com

# Check if Gateway rules are applying to HTTPS
curl -I https://malware.testing.google.test
```

## 📚 Troubleshooting

**Certificate Not Found:**
- Ensure you searched in the correct keychain (login vs system)
- Try searching for just "Cloudflare" or "Gateway"

**Trust Setting Greyed Out:**
- Certificate may be in System keychain (requires admin)
- Try the desktop script: `~/Desktop/trust_gateway_cert.sh`

**HTTPS Still Not Decrypted:**
- Restart your browser after configuring trust
- Check Gateway logs in Cloudflare dashboard
- Verify Gateway DNS is still configured on UCG

## 🎯 Expected Results

**Before Trust Configuration:**
- HTTPS traffic encrypted end-to-end
- HTTP rules only apply to non-encrypted traffic  
- Limited threat protection on HTTPS

**After Trust Configuration:**
- Gateway inspects all HTTPS traffic
- Full HTTP rule suite applies to HTTPS
- Complete threat protection across all protocols
- Enhanced security analytics available

---
*This configuration enables full Gateway protection across both HTTP and HTTPS traffic while respecting Microsoft 365 compliance requirements.*
