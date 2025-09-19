#!/bin/bash
# Gateway Monitor Agent Installation Script
# macOS Compatible

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="$HOME/.gateway-monitor"
SERVICE_NAME="gateway-monitor"
PLIST_PATH="$HOME/Library/LaunchAgents/com.bruteforce.gateway-monitor.plist"

echo "🔧 Installing Gateway Monitor Agent..."

# Create installation directory
mkdir -p "$INSTALL_DIR"

# Copy files
echo "📋 Copying files..."
cp "$SCRIPT_DIR/gateway_monitor.py" "$INSTALL_DIR/"
cp "$SCRIPT_DIR/config.json" "$INSTALL_DIR/"

# Make executable
chmod +x "$INSTALL_DIR/gateway_monitor.py"

# Install Python dependencies
echo "📦 Installing Python dependencies..."
python3 -m pip install requests

# Create logs directory
mkdir -p "$INSTALL_DIR/logs"

# Create LaunchAgent plist
echo "🚀 Creating LaunchAgent service..."
cat > "$PLIST_PATH" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.bruteforce.gateway-monitor</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>$INSTALL_DIR/gateway_monitor.py</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$INSTALL_DIR</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$INSTALL_DIR/logs/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>$INSTALL_DIR/logs/stderr.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>CF_API_EMAIL</key>
        <string>daniel@bruteforce.group</string>
        <key>CF_API_KEY</key>
        <string>9586ac5f9e8deaeffa283a83d137d265123fe</string>
    </dict>
</dict>
</plist>
EOF

# Load the service
echo "✅ Loading LaunchAgent service..."
launchctl load "$PLIST_PATH"

# Create management script
cat > "$INSTALL_DIR/manage.sh" << 'EOF'
#!/bin/bash
# Gateway Monitor Management Script

PLIST_PATH="$HOME/Library/LaunchAgents/com.bruteforce.gateway-monitor.plist"

case "$1" in
    start)
        echo "🚀 Starting Gateway Monitor..."
        launchctl load "$PLIST_PATH" 2>/dev/null || echo "Service already loaded"
        ;;
    stop)
        echo "⛔ Stopping Gateway Monitor..."
        launchctl unload "$PLIST_PATH" 2>/dev/null || echo "Service not loaded"
        ;;
    restart)
        echo "🔄 Restarting Gateway Monitor..."
        launchctl unload "$PLIST_PATH" 2>/dev/null || true
        sleep 2
        launchctl load "$PLIST_PATH"
        ;;
    status)
        echo "📊 Gateway Monitor Status:"
        if launchctl list | grep -q "com.bruteforce.gateway-monitor"; then
            echo "✅ Service is running"
            # Show last few log entries
            echo "📋 Recent logs:"
            tail -n 10 "$HOME/.gateway-monitor/gateway_monitor.log" 2>/dev/null || echo "No logs found"
        else
            echo "❌ Service is not running"
        fi
        ;;
    logs)
        echo "📋 Gateway Monitor Logs:"
        tail -f "$HOME/.gateway-monitor/gateway_monitor.log"
        ;;
    test)
        echo "🧪 Testing Gateway Monitor..."
        cd "$HOME/.gateway-monitor"
        python3 gateway_monitor.py --test
        ;;
    uninstall)
        echo "🗑️  Uninstalling Gateway Monitor..."
        launchctl unload "$PLIST_PATH" 2>/dev/null || true
        rm -f "$PLIST_PATH"
        echo "Service uninstalled. Files remain in $HOME/.gateway-monitor"
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs|test|uninstall}"
        exit 1
        ;;
esac
EOF

chmod +x "$INSTALL_DIR/manage.sh"

# Create symlink for easy access
mkdir -p "$HOME/.local/bin"
ln -sf "$INSTALL_DIR/manage.sh" "$HOME/.local/bin/gateway-monitor"

echo ""
echo "✅ Installation complete!"
echo ""
echo "📋 Management commands:"
echo "   gateway-monitor start     - Start the service"
echo "   gateway-monitor stop      - Stop the service"  
echo "   gateway-monitor restart   - Restart the service"
echo "   gateway-monitor status    - Check service status"
echo "   gateway-monitor logs      - View live logs"
echo "   gateway-monitor test      - Test configuration"
echo "   gateway-monitor uninstall - Remove the service"
echo ""
echo "📁 Installation directory: $INSTALL_DIR"
echo "📊 Service status:"
if launchctl list | grep -q "com.bruteforce.gateway-monitor"; then
    echo "✅ Gateway Monitor is running"
else
    echo "❌ Gateway Monitor failed to start - check logs"
fi
echo ""
echo "🔔 Desktop notifications are enabled by default"
echo "📧 To enable email notifications, edit: $INSTALL_DIR/config.json"
echo ""
echo "🎯 The agent will now monitor your Gateway logs every 5 minutes"
echo "   and notify you when rule adjustments are recommended!"
