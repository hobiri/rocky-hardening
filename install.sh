#!/bin/bash
set -e

URL="https://github.com/hobiri/rocky-hardening/archive/refs/tags/1.0.0-rc2.zip"
FILENAME="hardening.zip"

echo "Downloading..."
curl -L -o "$FILENAME" "$URL"

echo "Installing unzip if necessary..."
if ! command -v unzip &> /dev/null; then
    sudo dnf install -y unzip
fi

echo "Extracting..."
unzip -q "$FILENAME"

cd hardening
chmod +x rocky-hardening.sh
chmod +x steps/*

echo "Complete!"
