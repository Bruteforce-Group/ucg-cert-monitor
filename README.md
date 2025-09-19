# 🔍 Cloudflare Gateway Monitor Agent

An intelligent background monitoring agent that continuously analyzes Cloudflare Gateway logs and automatically detects when firewall rules need to be created, updated, or optimized.

## 🎯 Features

### Real-time Monitoring
- **Continuous Log Analysis**: Monitors Gateway logs every 5 minutes (configurable)
- **Intelligent Pattern Detection**: Uses ML-like algorithms to identify legitimate vs malicious traffic
- **Automatic Rule Recommendations**: Generates specific rule suggestions with confidence scores
- **Background Operation**: Runs as a macOS LaunchAgent service

### Smart Analysis Capabilities
- **🚫 Blocked Legitimate Traffic Detection**: Identifies when legitimate services are being blocked
- **🔒 Security Threat Detection**: Spots new threats that should be blocked (SQL injection, malware downloads)
- **📊 Traffic Pattern Analysis**: Detects bot traffic, anomalies, and optimization opportunities
- **🎯 Context-Aware Filtering**: Understands legitimate vs suspicious patterns based on domain, user-agent, etc.

### Multi-Channel Notifications
- **🔔 macOS Desktop Notifications**: Instant alerts for high-priority recommendations
- **📧 Email Notifications**: Detailed HTML reports with full analysis
- **🔗 Webhook Integration**: Slack/Teams/Discord notifications
- **📱 Priority-based Alerting**: Different notification levels for HIGH/MEDIUM/LOW priority issues

## 🚀 Quick Start

### Installation
```bash
# Navigate to the project directory
cd /Users/danielborrowman/ucg-cert-monitor

# Run the installation script
chmod +x install.sh
./install.sh
```

### Management Commands
```bash
# Check service status
gateway-monitor status

# View live logs
gateway-monitor logs

# Restart the service
gateway-monitor restart

# Stop monitoring
gateway-monitor stop
```

## 📊 Example Output

When the agent detects issues, you'll receive notifications like:

```
🚨 Gateway Rule Alert
Found 2 high-priority rule recommendations:

HIGH Priority - ALLOW app-site-association.cdn-apple.com
Reason: Legitimate Apple CDN blocked 47 times
Confidence: 89%
Evidence: Status 403 count: 47, Known legitimate domain

MEDIUM Priority - BLOCK suspicious-domain.example
Reason: Potential SQL injection detected
Confidence: 76%
Evidence: URI contains SELECT statements, Multiple attempts
```

## 🧠 How It Works

The agent continuously:
1. **Fetches logs** from Cloudflare Log Explorer API
2. **Analyzes patterns** using intelligent algorithms
3. **Generates recommendations** with confidence scores
4. **Sends notifications** based on priority levels
5. **Stores history** for trend analysis

## ⚙️ Configuration

Edit `~/.gateway-monitor/config.json` to customize monitoring intervals, notification preferences, and analysis thresholds.

## 🔧 Advanced Features

- **SQLite Database**: Stores all recommendations and analysis history
- **Priority System**: HIGH/MEDIUM/LOW priority recommendations
- **Confidence Scoring**: Each recommendation includes confidence percentage
- **Historical Tracking**: Monitor rule effectiveness over time
- **Multi-notification**: Desktop, email, and webhook alerts

## 📈 Benefits

- **Reduces False Positives**: Automatically identifies blocked legitimate traffic
- **Improves Security**: Detects new threats that bypass existing rules
- **Saves Time**: No manual log analysis required
- **Prevents Downtime**: Proactive identification of service disruptions
- **Audit Trail**: Complete history of all recommendations and changes

---

**🎯 Ready to start intelligent Gateway monitoring? Run `./install.sh` to get started!**
