#!/bin/bash

echo "Cleaning Mininet..."
sudo mn -c

echo "Starting POX Firewall..."
cd ~/pox
./pox.py firewall &
sleep 3

echo "Starting Mininet..."
sudo mn --controller=remote --topo=single,6 --mac

chmod +x run.sh

./run.sh