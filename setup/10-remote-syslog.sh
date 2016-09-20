#!/bin/bash
#

[ -f defaults.conf ] && . defaults.conf
[ -f env.conf ] && . env.conf

### elasticsearch ------------------------------------------------------------

cat <<EOF |sudo tee /etc/logstash/conf.d/10-remote-syslog.conf
input {
  syslog {
    port => "$port_syslog"
    type => "syslog"
    add_field => { "received_at" => "%{@timestamp}" }
    add_field => { "[@metadata][output]" => "self" }
  }
}

filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "IN=(%{DATA:fw_if_in})? OUT=(%{DATA:fw_if_out})? (MAC=%{DATA} )?SRC=%{IP:fw_src_ip} DST=%{IP:fw_dst_ip} LEN=%{NUMBER:fw_len:int} %{GREEDYDATA:fw_tcp_opts} PROTO=%{WORD:fw_proto} (SPT=%{INT:fw_src_port} DPT=%{INT:fw_dst_port} )?%{GREEDYDATA:fw_tcp_opts}" }
      add_tag => [ "iptables" ]
      add_field => { }
    }
    if "iptables" in [tags] {
      grok {
        match => { "message" => "\[VFW-%{NOTSPACE:fw_name}-%{WORD:fw_rule}-%{WORD:fw_action}\]" }
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
    } else {
      if "_grokparsefailure" in [tags] {
        grok {
          match => { "message" => "Delete SA(.*) payload: deleting IPSEC" }
          add_tag => [ "ipsec", "vpn" ]
          remove_tag => [ "_grokparsefailure" ]
        }
      }
      if "_grokparsefailure" in [tags] {
        grok {
          match => { "message" => "IPsec SA established" }
          add_tag => [ "ipsec", "vpn" ]
          add_field => { "event" => "ipsec sa established" }
          remove_tag => [ "_grokparsefailure" ]
        }
      }
      if "_grokparsefailure" in [tags] {
        grok {
          match => { "message" => "peer-%{IP:ipsec_peer_addr}-tunnel-vti.* #%{NUMBER:ipsec_id}: initiating Quick Mode %{GREEDYDATA:ipsec_mode} to replace #%{NUMBER:ipsec_id_old} {using isakmp#%{NUMBER:isakmp_id}}" }
          add_tag => [ "ipsec", "vpn" ]
          add_field => { "event" => "ipsec initiating quick mode" }
          remove_tag => [ "_grokparsefailure" ]
        }
      }
      if "_grokparsefailure" in [tags] {
        grok {
          match => { "message" => "Vendor ID payload" }
          add_tag => [ "ipsec", "vpn" ]
          remove_tag => [ "_grokparsefailure" ]
        }
      }
      if "_grokparsefailure" in [tags] {
        grok {
          match => { "message" => "ISAKMP SA established" }
          add_tag => [ "ipsec", "vpn" ]
          add_field => { "event" => "isakmp sa established" }
          remove_tag => [ "_grokparsefailure" ]
        }
      }
      if "_grokparsefailure" in [tags] {
        grok {
          match => { "message" => "peer-%{IP:ipsec_peer_addr}-tunnel-vti.* #%{NUMBER:ipsec_id}: initiating Main Mode to replace #%{NUMBER:ipsec_id_old}" }
          add_tag => [ "ipsec", "vpn" ]
          add_field => { "event" => "ipsec initiating main mode" }
          remove_tag => [ "_grokparsefailure" ]
        }
      }
      if ("/USR/SBIN/CRON" == [program] or "CRON" == [program])
        and [severity] > 5 {
        mutate {
          replace => { "program" => "CRON" }
          add_tag => [ "_verbose" ]
          remove_tag => [ "_grokparsefailure" ]
        }
      }
      if "_grokparsefailure" in [tags] and [program] == "sudo" {
        grok {
          match => { "message" => "%{USERNAME:user} : TTY=%{NOTSPACE:tty} ; PWD=%{PATH:pwd} ; USER=%{USERNAME:switched_to} ; COMMAND=%{GREEDYDATA:command}" }
          add_tag => [ "security" ]
          add_field => { "event" => "sudo by %{user} as %{switched_to}" }
          remove_tag => [ "_grokparsefailure" ]
        }
      }
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
