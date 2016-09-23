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
    mutate {
      add_field => { "[nms][pod]" => "%{host} pod" }
      add_field => { "[nms][account]" => "%{host} account" }
      add_field => { "[nms][hostname]" => "%{host} hostname" }
    }
    translate {
      field => "[nms][pod]"
      destination => "[nms][pod]"
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

    translate {
      field => "[netflow][protocol]"
      destination => "[nms][protocol]"
      dictionary => ["6","TCP", "17","UDP", "1","ICMP", "47","GRE", "50","ESP"]
      fallback => "%{[netflow][protocol]}"
    }
    if [netflow][input_snmp] > 0 {
      mutate {
        add_field => { "[nms][zone]" => "%{host} ifno %{[netflow][input_snmp]}" }
        add_field => { "[nms][direction]" => "inbound" }
      }
    } else if [netflow][output_snmp] > 0 {
      mutate {
        add_field => { "[nms][zone]" => "%{host} ifno %{[netflow][output_snmp]}" }
        add_field => { "[nms][direction]" => "outbound" }
      }
    }
    translate {
      field => "[nms][zone]"
      destination => "[nms][zone]"
      override => true
      dictionary_path => "$config_dir/dict.device-map.yml"
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
      add_field => { "[nms][session]" => "%{[netflow][ipv4_dst_addr]}:%{[netflow][l4_dst_port]}-%{[netflow][ipv4_src_addr]}:%{[netflow][l4_src_port]}" }
    }
  }
  if [nms][direction] == "outbound" {
    mutate {
      add_field => { "[nms][session]" => "%{[netflow][ipv4_src_addr]}:%{[netflow][l4_src_port]}-%{[netflow][ipv4_dst_addr]}:%{[netflow][l4_dst_port]}" }
    }
  }
}

output {
  if [type] == "netflow" {
    elasticsearch {
      hosts => ["127.0.0.1"]
      index => "netflow-%{+YYYY.MM.dd}"
    }
  }
}
EOF

# upload mapping template
curl -XPUT localhost:9200/_template/netflow \
           -d @$assets_dir/template-netflow.json

# setup firewall
cat <<EOF |sudo tee /etc/ufw/applications.d/hce-netflow
[HCE-Logstash-NetFlow]
title=HCE-Logstash-NetFlow
description=Logstash NetFlow
ports=$port_netflow/udp
EOF

sudo ufw allow from any to any app HCE-Logstash-NetFlow
