#!/bin/bash

# restart firewall and logstash shipper
sudo ufw reload
sudo systemctl restart logstash.service

ls /var/lib/elasticsearch/hyeoncheon/nodes/0/indices/
