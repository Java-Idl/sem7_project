#!/bin/bash
# PeripheralShield Native Host Installer for Linux & macOS

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
MANIFEST="$DIR/com.defensive.extension.host.json"

chmod +x "$DIR/host.py"
chmod +x "$DIR/host.js"

# Linux Chrome & Chromium target directories
TARGET_DIRS=(
  "$HOME/.config/google-chrome/NativeMessagingHosts"
  "$HOME/.config/chromium/NativeMessagingHosts"
  "$HOME/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts"
  "$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
  "$HOME/Library/Application Support/Chromium/NativeMessagingHosts"
)

# Update host path in manifest for unix
sed -i.bak 's/"path": "host.bat"/"path": "'"$DIR"'\/host.py"/' "$MANIFEST" 2>/dev/null || sed -i '' 's/"path": "host.bat"/"path": "'"$DIR"'\/host.py"/' "$MANIFEST"

for TARGET in "${TARGET_DIRS[@]}"; do
  if [ -d "$(dirname "$TARGET")" ]; then
    mkdir -p "$TARGET"
    cp "$MANIFEST" "$TARGET/"
    echo "Registered in $TARGET"
  fi
done

echo "PeripheralShield Native Messaging Host installed."
