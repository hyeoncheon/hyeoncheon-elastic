#!/bin/bash
#

[ -f defaults.conf ] && . defaults.conf
[ -f env.conf ] && . env.conf

### elasticsearch ------------------------------------------------------------

cat <<EOF |sudo tee /etc/logstash/conf.d/10-remote-syslog.conf
input {
  syslog {
    tags => [ "no_default_out" ]
    port => "$port_syslog"
    type => "syslog"
    add_field => [ "received_at", "%{@timestamp}" ]
  }
}

filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "IN=(%{DATA:fw_if_in})? OUT=(%{DATA:fw_if_out})? (MAC=%{DATA} )?SRC=%{IP:fw_src_ip} DST=%{IP:fw_dst_ip} LEN=%{NUMBER:fw_len:int} %{GREEDYDATA:fw_tcp_opts} PROTO=%{WORD:fw_proto} SPT=%{INT:fw_src_port} DPT=%{INT:fw_dst_port} %{GREEDYDATA:fw_tcp_opts}" }
      add_tag => [ "iptables" ]
      add_field => {
      }
    }
  }
  if "iptables" in [tags] {
    grok {
      match => { "message" => "\[VFW-%{NOTSPACE:fw_name}-%{WORD:fw_rule}-%{WORD:fw_action}\]" }
    }
  }
  if [fw_src_ip] {
    geoip {
      source => "fw_src_ip"
      target => "src_geo"
      fields => [ "city_name", "country_code3", "location", "ip" ]
    }
  }
  if [fw_dst_ip] {
    geoip {
      source => "fw_dst_ip"
      target => "dst_geo"
      fields => [ "city_name", "country_code3", "location", "ip" ]
    }
  }
}

output {
  if [type] == "syslog" {
    elasticsearch {
      hosts => ["127.0.0.1"]
      index => "syslog-%{+YYYY.MM.dd}"
      template => "/home/azmin/hyeoncheon-elastic/setup/template-syslog.json"
      template_name => "syslog"
    }
  }
}
EOF

mkdir -p backups
sudo cp -a /etc/ufw/before.rules backups/configure-backup.before-rules
sudo sed -i '/HCE START/,/HCE END/d' /etc/ufw/before.rules

cat <<EOF |sudo tee -a /etc/ufw/before.rules
# HCE START: Logstash remote syslog
*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [0:0]
-F
-A PREROUTING -p udp -m udp --dport 514 -j REDIRECT --to-ports $port_syslog
-A PREROUTING -p tcp -m tcp --dport 514 -j REDIRECT --to-ports $port_syslog
COMMIT
# HCE END: Logstash remote syslog
EOF

sudo diff -u backups/configure-backup.before-rules /etc/ufw/before.rules

cat <<EOF |sudo tee /etc/ufw/applications.d/hce-logstash
[HCE-Logstash]
title=HCE-Logstash
description=Logstash Syslog
ports=$port_syslog/udp
EOF

sudo ufw allow from any to any app HCE-Logstash
sudo ufw reload

sudo systemctl restart logstash.service
