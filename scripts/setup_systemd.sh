#!/bin/bash

# Create logs directory
mkdir -p logs

# Copy service files to systemd user directory
mkdir -p ~/.config/systemd/user
cp apt-ack.service ~/.config/systemd/user/
cp apt-ack.timer ~/.config/systemd/user/

# Reload systemd
systemctl --user daemon-reload

# Enable and start timer
systemctl --user enable apt-ack.timer
systemctl --user start apt-ack.timer

echo "APT-ACK systemd timer installed and started"
echo ""
echo "Useful commands:"
echo "  systemctl --user status apt-ack.timer    # Check timer status"
echo "  systemctl --user list-timers             # List all timers"
echo "  systemctl --user start apt-ack.service   # Run collection now"
echo "  journalctl --user -u apt-ack.service -f  # View logs"
echo "  systemctl --user stop apt-ack.timer      # Stop timer"