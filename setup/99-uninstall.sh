#!/bin/bash
#

[ -f defaults.conf ] && . defaults.conf
[ -f env.conf ] && . env.conf

sudo rm -f /etc/ufw/applications.d/hce-*
sudo rm -f /etc/logstash/conf.d/*

sudo systemctl stop logstash.service

sudo apt-get remove -y --purge elasticsearch
sudo apt-get remove -y --purge logstash
sudo apt-get remove -y --purge kibana

echo $* |grep -q clean && {
	sudo rm -f /etc/apt/sources.list.d/elasticstack-2.x.list
	sudo rm -rf /etc/elasticsearch
	sudo rm -rf /etc/logstash
	sudo rm -rf /var/log/elasticsearch
	sudo rm -rf /var/log/logstash
	sudo rm -rf /var/lib/elasticsearch
	sudo rm -rf /var/lib/logstash
}

mkdir -p backups
sudo cp -a /etc/ufw/before.rules backups/uninstall-backup.before-rules
sudo sed -i '/HCE START/,/HCE END/d' /etc/ufw/before.rules
sudo diff -u backups/uninstall-backup.before-rules /etc/ufw/before.rules

sudo ufw delete allow from 211.45.60.0/24 to any app HCE-Kibana
sudo ufw delete allow from any to any app HCE-Logstash
sudo ufw reload
sudo ufw status

echo "
# CAUTION 
  package 'openjdk-8-jre-headless' is installed for elasticsearch.
  remove it manually if you do not need it anymore.

  sudo apt-get remove openjdk-8-jre-headless

  ufw configuration '/etc/ufw/before.rules' is modified by it.
  review it for your needs. (backup is stored as uninstall-backup.before-rules)
"

