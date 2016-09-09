#!/bin/bash
#
set -x

[ -f defaults.conf ] && . defaults.conf
[ -f env.conf ] && . env.conf

### installation -------------------------------------------------------------

GPG_KEY=https://packages.elastic.co/GPG-KEY-elasticsearch
wget -qO - $GPG_KEY | sudo apt-key add -

cat <<EOF |sudo tee /etc/apt/sources.list.d/elasticstack-2.x.list
deb https://packages.elastic.co/elasticsearch/2.x/debian stable main
deb https://packages.elastic.co/logstash/2.4/debian stable main
deb https://packages.elastic.co/kibana/4.6/debian stable main
EOF

# pre-requirements
sudo apt-get install -y openjdk-8-jre-headless
# install elk packages
sudo apt-get update
sudo apt-get install -y elasticsearch
sudo apt-get install -y logstash
sudo apt-get install -y kibana

# setup elasticsearch cluster
sudo sed -i "s/.*cluster.name: .*/cluster.name: $cluster_name/" \
	/etc/elasticsearch/elasticsearch.yml

# setup default logstash configuration
cat <<EOF |sudo tee /etc/logstash/conf.d/99-local-elastic.conf
input {
  file {
    type => "syslog-local"
    path => [ "/var/log/elasticsearch/*.log", "/var/log/logstash/*.log" ]
  }
}
output {
  if "no_default_out" not in [tags] {
    elasticsearch {
      hosts => ["127.0.0.1"]
    }
  }
}
EOF

### setup firewall -----------------------------------------------------------
cat <<EOF |sudo tee /etc/ufw/applications.d/hce-kibana
[HCE-Kibana]
title=HCE-Kibana
description=Kibana
ports=$kibana_port/tcp
EOF

sudo ufw allow from $admin_network to any app HCE-Kibana
sudo ufw reload

### start services -----------------------------------------------------------
sudo systemctl daemon-reload
sudo systemctl enable elasticsearch.service
sudo systemctl enable logstash.service
sudo systemctl enable kibana.service
sudo systemctl restart elasticsearch.service
sudo systemctl restart kibana.service
sleep 10
sudo systemctl restart logstash.service

