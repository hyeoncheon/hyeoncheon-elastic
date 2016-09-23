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
    if [device] {
      mutate {
        add_tag => [ "snmp" ]
        add_field => { "[nms][pod]" => "%{device} pod" }
        add_field => { "[nms][zone]" => "%{device} if %{ifname}" }
        add_field => { "[nms][account]" => "%{device} account" }
        add_field => { "[nms][hostname]" => "%{device} hostname" }
      }
      translate {
        field => "[nms][pod]"
        destination => "[nms][pod]"
        override => true
        dictionary_path => "$config_dir/dict.device-map.yml"
      }
      translate {
        field => "[nms][zone]"
        destination => "[nms][zone]"
        override => true
        dictionary_path => "$config_dir/dict.device-map.yml"
      }
      translate {
        field => "[nms][account]"
        destination => "[nms][account]"
        override => true
        dictionary_path => "$config_dir/dict.device-map.yml"
      }
      translate {
        field => "[nms][hostname]"
        destination => "[nms][hostname]"
        override => true
        dictionary_path => "$config_dir/dict.device-map.yml"
      }
    } else {
      mutate {
        add_tag => [ "ping" ]
        add_field => { "[nms][pod]" => "global" }
        add_field => { "[nms][zone]" => "global" }
        add_field => { "[nms][account]" => "global" }
        add_field => { "[nms][hostname]" => "global" }
      }
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
curl -XPUT localhost:9200/_template/snmp \
           -d @$assets_dir/template-snmp.json

# setup firewall
cat <<EOF |sudo tee /etc/ufw/applications.d/hce-snmp
[HCE-Logstash-SNMP]
title=HCE-Logstash-SNMP
description=Logstash SNMP
ports=$port_snmp/udp
EOF

sudo ufw allow from any to any app HCE-Logstash-SNMP
