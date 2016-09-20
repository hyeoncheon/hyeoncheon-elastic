#!/bin/bash
#

[ -f defaults.conf ] && . defaults.conf
[ -f env.conf ] && . env.conf

### elasticsearch ------------------------------------------------------------

cat <<EOF |sudo tee /etc/logstash/conf.d/20-netflow.conf
input {
  udp {
    type => "netflow"
    port => "$port_netflow"
    codec => netflow
    add_field => { "received_at" => "%{@timestamp}" }
    add_field => { "[@metadata][output]" => "self" }
  }
}

filter {
  if [type] == "netflow" {
    translate {
      field => "[netflow][protocol]"
      destination => "[nms][protocol]"
      dictionary => ["6","TCP", "17","UDP", "1","ICMP", "47","GRE", "50","ESP"]
      fallback => "%{[netflow][protocol]}"
    }
    if [netflow][input_snmp] > 0 {
      translate {
        field => "[netflow][input_snmp]"
        destination => "[nms][interface]"
        dictionary => ["8","in", "9","sl", "10","dbz", "11","dev", "12","app" ]
        fallback => "%{[netflow][input_snmp]}"
        add_field => { "[nms][direction]" => "inbound" }
      }
    }
    if [netflow][output_snmp] > 0 {
      translate {
        field => "[netflow][output_snmp]"
        destination => "[nms][interface]"
        dictionary => ["8","in", "9","sl", "10","dbz", "11","dev", "12","app" ]
        fallback => "%{[netflow][output_snmp]}"
        add_field => { "[nms][direction]" => "outbound" }
      }
    }
    ruby {
      init => "require 'time'"
      code => "
        last = Time.iso8601(event['[netflow][last_switched]']).to_f;
        first = Time.iso8601(event['[netflow][first_switched]']).to_f;
        bits = event['[netflow][in_bytes]'] * 8;
        event['[nms][duration]'] = last - first;
        event['[nms][bps]'] = bits / (last - first) if (last - first) > 0;
      "
    }
    date {
      match => [ "[netflow][last_switched]", "ISO8601" ]
    }
  }
  if [nms][direction] == "inbound" {
    mutate {
      add_field => { "[nms][sequence]" => "%{[netflow][ipv4_dst_addr]}:%{[netflow][l4_dst_port]}-%{[netflow][ipv4_src_addr]}:%{[netflow][l4_src_port]}" }
    }
  }
  if [nms][direction] == "outbound" {
    mutate {
      add_field => { "[nms][sequence]" => "%{[netflow][ipv4_src_addr]}:%{[netflow][l4_src_port]}-%{[netflow][ipv4_dst_addr]}:%{[netflow][l4_dst_port]}" }
    }
  }
}

output {
  if [type] == "netflow" {
    elasticsearch {
      hosts => ["127.0.0.1"]
      index => "nms-%{+YYYY.MM.dd}"
    }
  }
}
EOF

# upload mapping template
curl -XPUT localhost:9200/_template/nms -d @template-netflow.json

# install translate plugin
/opt/logstash/bin/logstash-plugin list |grep -q filter-translate || \
	sudo /opt/logstash/bin/logstash-plugin install logstash-filter-translate


cat <<EOF |sudo tee /etc/ufw/applications.d/hce-netflow
[HCE-Logstash-NetFlow]
title=HCE-Logstash-NetFlow
description=Logstash NetFlow
ports=$port_netflow/udp
EOF

sudo ufw allow from any to any app HCE-Logstash-NetFlow
sudo ufw reload

sudo systemctl restart logstash.service
