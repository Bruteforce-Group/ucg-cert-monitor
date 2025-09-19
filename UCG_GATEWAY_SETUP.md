# UCG Cloudflare Gateway Configuration Guide

## 🎯 Objective
Configure your UniFi Cloud Gateway Fiber to use Cloudflare Gateway DNS, activating your 60 security rules network-wide.

## 🔧 Configuration Steps

### 1. Access UniFi Controller
- URL: `https://192.168.22.1:8443` 
- Or: `https://unifi.bozza.au` (via tunnel)
- Login with your UniFi credentials

### 2. Navigate to WAN Settings
```
Settings → Internet → WAN Configuration
```

### 3. Configure DNS Servers
- Change DNS from "Auto" to "Manual"
- Primary DNS: `172.64.36.1`
- Secondary DNS: `172.64.36.2`

### 4. Apply and Test
- Click "Apply Changes"
- Wait for provisioning to complete
- Test with: `nslookup google.com 192.168.22.1`

## 🎯 Expected Results

### Before Configuration
- Network DNS: Telstra ISP servers
- Gateway Rules: Inactive (0/60 rules protecting traffic)
- Security: Basic ISP filtering only

### After Configuration  
- Network DNS: Cloudflare Gateway
- Gateway Rules: Active (60/60 rules protecting traffic)
- Security: Full malware, phishing, and custom protection

## 🧪 Testing Gateway Activation

Test these commands after configuration:

```bash
# Should resolve through Gateway
nslookup google.com 192.168.22.1

# Should be blocked if Gateway is active  
nslookup malware.testing.google.test 192.168.22.1

# Test your Mac's DNS (should now use Gateway)
nslookup google.com
```

## 📊 Gateway Rules That Will Activate

Your configured rules include:
- ✅ DNS security threat categories (malware, phishing, C&C)
- ✅ HTTP security categories with certificate validation
- ✅ Executable download blocking
- ✅ P2P and mining port blocking  
- ✅ Suspicious admin path blocking
- ✅ High-risk country blocking
- ✅ Custom security rules (60 total)

## 🔍 Verification Commands

After configuration, verify Gateway is active:

```bash
# Run the dynamic test suite
python3 test_all_gateway_rules_dynamic.py

# Check DNS resolution path
python3 -c "
import socket
print('DNS servers now in use:')
result = socket.getaddrinfo('google.com', 80)
print(f'Resolved via configured DNS')
"

# Test specific Gateway functionality
curl -H 'accept: application/dns-json' \
'https://n4hymsry2w.cloudflare-gateway.com/dns-query?name=google.com&type=A'
```

## 📞 Support

If you encounter issues:
1. Check UniFi Controller logs
2. Verify internet connectivity after changes
3. Test DNS resolution manually
4. Revert to "Auto" DNS if problems persist

---
*This configuration will activate network-wide Cloudflare Gateway protection*
