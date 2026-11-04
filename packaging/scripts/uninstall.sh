#!/bin/sh
# Removes Overlord. Needs root. Quarantined files stay in /var/db/overlord/quarantine until you
# delete that directory yourself.
set -u
launchctl bootout system/com.overlord.daemon 2>/dev/null
console_uid=$(stat -f %u /dev/console)
launchctl bootout "gui/$console_uid/com.overlord.notify" 2>/dev/null
rm -f /Library/LaunchDaemons/com.overlord.daemon.plist /Library/LaunchAgents/com.overlord.notify.plist
pfctl -a overlord -F all 2>/dev/null
rm -f /etc/pf.anchors/overlord
sed -i '' '/^anchor "overlord"$/d;/^load anchor "overlord"/d' /etc/pf.conf
pfctl -f /etc/pf.conf 2>/dev/null
rm -rf /Library/Overlord /var/run/overlord.sock
echo "overlord removed; /var/db/overlord kept (logs, labels, quarantine)"
