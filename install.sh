#!/bin/bash
set -e

VERSION="1.0.0-rc2"
URL="https://github.com/hobiri/rocky-hardening/archive/refs/tags/${VERSION}.zip"
FILENAME="rocky-hardening-${VERSION}.zip"

echo "Downloading..."
curl -L -o "$FILENAME" "$URL"

echo "Installing unzip if necessary..."
if ! command -v unzip &> /dev/null; then
    sudo dnf install -y unzip
fi

echo "Extracting..."
unzip -q "$FILENAME"
rm -f "$FILENAME"

echo "Setting permissions..."
cd "rocky-hardening-${VERSION}"
chmod +x rocky-hardening.sh
chmod +x steps/*

echo "Complete!"
