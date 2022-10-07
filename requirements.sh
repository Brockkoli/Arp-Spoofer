#!/bin/bash
echo "Running update and upgrade..."
apt-get update -y && apt-get upgrade -y

echo "Installing Python3..."
sudo apt-get install python3

echo "Installing Scapy..."
sudo apt install python3-scapy

echo "Installing pyfiglet..."
sudo apt install python3-pyfiglet