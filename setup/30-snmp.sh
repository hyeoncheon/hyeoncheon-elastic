#!/bin/bash
#

[ -f defaults.conf ] && . defaults.conf
[ -f env.conf ] && . env.conf

### elasticsearch ------------------------------------------------------------

cat <<EOF |sudo tee /etc/logstash/conf.d/30-snmp.conf
input {
  udp {
    type => snmp
    port => "$port_snmp"
    codec => json_lines
    add_field => { "received_at" => "%{@timestamp}" }
    add_field => { "[@metadata][output]" => "self" }
  }
}

filter {
  if [type] == "snmp" {
    date {
      match => [ "timestamp", "ISO8601" ]
    }
    mutate {
      add_field => { "proxy" => "%{host}" }
    }
  }
}

output {
  if [type] == "snmp" {
    elasticsearch {
      hosts => ["127.0.0.1"]
      index => "snmp-%{+YYYY.MM.dd}"
    }
  }
}
EOF

# upload mapping template
#curl -XDELETE localhost:9200/snmp-2016.09.14
curl -XPUT localhost:9200/_template/snmp -d @template-snmp.json

# install translate plugin
#/opt/logstash/bin/logstash-plugin list |grep -q filter-translate || \
#	sudo /opt/logstash/bin/logstash-plugin install logstash-filter-translate

cat <<EOF |sudo tee /etc/ufw/applications.d/hce-snmp
[HCE-Logstash-SNMP]
title=HCE-Logstash-SNMP
description=Logstash SNMP
ports=$port_snmp/udp
EOF

sudo ufw allow from any to any app HCE-Logstash-SNMP
sudo ufw reload

sudo systemctl restart logstash.service
