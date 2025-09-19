# Cloudflare WARP Zero Trust Enrollment Guide

## 🎯 Objective
Enroll your Mac's WARP client with the "bruteforcegroup" Zero Trust organization to enable enterprise-grade security and access controls.

## 📱 Current WARP Status
- **WARP CLI**: Installed (version 2025.6.824.1) ✅
- **Application**: Opened and ready for configuration ✅
- **Current Status**: Free account registration needs replacement
- **Target Organization**: bruteforcegroup

## 🔧 Manual Zero Trust Enrollment Steps

### Method 1: GUI Enrollment (Recommended)

1. **Open WARP Application** (should already be open)
   - Look for the Cloudflare WARP icon in your menu bar
   - If not visible, open from Applications or Spotlight

2. **Access Account Settings**
   - Click the WARP icon in the menu bar
   - Click on "Preferences" or the gear icon
   - Look for "Account" or "Teams" settings

3. **Switch to Zero Trust**
   - Look for "Switch to Teams" or "Zero Trust" option
   - Click "Use with Teams" or similar option

4. **Enter Organization**
   - When prompted for organization/team name, enter: **`bruteforcegroup`**
   - Click "Next" or "Continue"

5. **Authenticate**
   - This will open your browser to: `https://bruteforcegroup.cloudflareaccess.com/warp`
   - Login with your organization credentials
   - Complete any required authentication (MFA, SSO, etc.)

6. **Complete Enrollment**
   - Return to WARP app after browser authentication
   - Device should now show as enrolled with bruteforcegroup

### Method 2: CLI Enrollment (Alternative)

If GUI enrollment doesn't work, try these CLI commands:

```bash
# Clear any existing registration
warp-cli registration delete

# Create new registration (will open browser)
warp-cli registration new

# In the browser, navigate to:
# https://bruteforcegroup.cloudflareaccess.com/warp
```

### Method 3: Direct URL Enrollment

If other methods fail:

1. **Open Browser** and navigate to:
   ```
   https://bruteforcegroup.cloudflareaccess.com/warp
   ```

2. **Login** with your organization credentials

3. **Download/Install** device certificate if prompted

4. **Restart WARP** application after authentication

## 🔍 Verification Commands

After enrollment, verify with these commands:

```bash
# Check organization enrollment
warp-cli registration organization

# Check connection status  
warp-cli status

# View account information
warp-cli registration show

# Test Zero Trust connection
warp-cli connect
```

## 📊 Expected Results After Enrollment

**Before Zero Trust Enrollment:**
- Account Type: Free
- Organization: None
- Policies: Consumer defaults
- DNS: Cloudflare public DNS

**After Zero Trust Enrollment:**
- Account Type: Zero Trust/Teams
- Organization: bruteforcegroup ✅
- Policies: Organization-defined policies
- DNS: Gateway DNS with your 47 security rules ✅

## 🛡️ Zero Trust Benefits

Once enrolled with bruteforcegroup:

- ✅ **Enterprise Policies**: Organization-defined security policies
- ✅ **Device Trust**: Device posture and compliance checking
- ✅ **Network Segmentation**: Access to private networks and applications
- ✅ **Enhanced Logging**: Detailed activity and security logs
- ✅ **Centralized Management**: IT admin control and monitoring
- ✅ **Integration**: Works with existing Gateway rules (47 rules active)

## 🔧 Network Integration

**WARP + Gateway Integration:**
- **DNS Resolution**: WARP → Gateway DNS (172.64.36.1/2) ✅
- **HTTPS Decryption**: WARP + Gateway certificate ✅
- **Security Rules**: All 47 Gateway rules apply to WARP traffic ✅
- **Network Protection**: Full Zero Trust network security ✅

## 🚨 Troubleshooting

**Cannot Find Organization:**
- Verify organization name: `bruteforcegroup`
- Check if your account has been invited to the organization
- Contact your IT admin for Zero Trust enrollment

**Browser Authentication Fails:**
- Clear browser cache and cookies
- Try incognito/private browsing mode
- Ensure you're using organization credentials (not personal)

**WARP Won't Connect After Enrollment:**
- Restart WARP application
- Check firewall settings
- Verify network connectivity

**DNS Resolution Issues:**
- Ensure Gateway DNS is still configured on UCG
- Check WARP DNS settings match Gateway
- Verify both systems are working together

## 📱 Mobile Device Enrollment

If you need to enroll mobile devices:

**iOS/Android:**
1. Install Cloudflare WARP app
2. Open app and tap "Use with Teams"  
3. Enter: `bruteforcegroup`
4. Complete authentication in browser
5. Return to app to complete enrollment

## 🎯 Final Configuration Check

After successful enrollment, verify:

```bash
# Should show: bruteforcegroup
warp-cli registration organization

# Should show: Connected with Zero Trust policies
warp-cli status

# Should show enhanced DNS resolution
dig @172.64.36.1 google.com

# Test malware blocking (should be blocked)
curl -I https://malware.testing.google.test
```

## 📞 Support Resources

**Organization Support:**
- IT Admin: Check with bruteforcegroup IT team
- Support URL: Check `warp-cli settings support-url`

**Cloudflare Documentation:**
- [Zero Trust WARP Deployment](https://developers.cloudflare.com/cloudflare-one/connections/connect-devices/warp/)
- [Device Enrollment](https://developers.cloudflare.com/cloudflare-one/connections/connect-devices/warp/deployment/device-enrollment/)

---

*Once enrolled, your Mac will have enterprise-grade Zero Trust protection integrated with your existing Gateway security rules.*
