#!/bin/bash
#

[ -f defaults.conf ] && . defaults.conf
[ -f env.conf ] && . env.conf

### elasticsearch ------------------------------------------------------------

cat <<EOF |sudo tee /etc/logstash/conf.d/80-alert.conf
filter {
  if [type] == "snmp" {
    if [tx_bps] and ([tx_bps] > $snmp_high_traffic) and [nms][zone] == "fcz" {
      mutate { add_tag => [ "alert" ] }
      clone {
        add_field => { "trap" => "snmp_high_traffic" }
        add_field => { "origin" => "snmp" }
        clones => [ "alert" ]
      }
    }
    if [ping_count] and ([ping_count] < 3 or [ping_rtt_ms] > $snmp_low_latency) {
      mutate { add_tag => [ "alert" ] }
      clone {
        add_field => { "trap" => "snmp_low_latency" }
        add_field => { "origin" => "ping" }
        clones => [ "alert" ]
      }
    }
  }

  if [type] == "syslog" {
    if "$hc_alrt" in [message] or ([severity] and [severity] < 4) {
      if [program] not in [ "pptpd", "pppd" ] {
        mutate { add_tag => [ "alert" ] }
        clone {
          add_field => { "trap" => "syslog_alert" }
          add_field => { "origin" => "syslog" }
          clones => [ "alert" ]
        }
      }
    }
  }

  if [type] == "netflow" {
    if [netflow][in_bytes] and [netflow][in_bytes] >= $netflow_high_traffic and [nms][zone] == "fcz" {
      mutate { add_tag => [ "alert" ] }
      clone {
        add_field => { "trap" => "netflow_high_traffic" }
        add_field => { "origin" => "netflow" }
        clones => [ "alert" ]
      }
    }
  }



  if [type] == "alert" {
    mutate {
      add_field => { "[@metadata][output]" => "self" }
    }
    if [trap] == "snmp_high_traffic" {
      ruby {
        code => "
          event['alert_what'] = 'Rx: ' +
            event['rx_bps'].round.to_s.gsub(/(\d)(?=(\d{3})+$)/,'\1,') + ' B/s
Tx: ' +
            event['tx_bps'].round.to_s.gsub(/(\d)(?=(\d{3})+$)/,'\1,') + ' B/s';
        "
      }
      mutate {
        add_field => { "alert_where" => "%{[nms][hostname]}
%{[nms][zone]} (%{ifname})" }
        add_field => { "alert_message" => "*High Traffic!* %{[nms][account]} %{[nms][zone]} zone (%{[nms][hostname]} %{ifname})" }
        add_field => { "alert_color" => "warning" }
      }
    }
    if [trap] == "snmp_low_latency" {
      ruby {
        code => "
          event['alert_what'] = 'RTT: ' + event['ping_rtt_ms'].round.to_s +
                                'ms (' + event['ping_count'].to_s + ' times)';
        "
      }
      mutate {
        add_field => { "alert_where" => "%{ping_addr}" }
        add_field => { "alert_message" => "*High Latency!* to %{ping_name}" }
        add_field => { "alert_color" => "warning" }
      }
    }

    if [trap] == "syslog_alert" {
      mutate {
        lowercase => [ "severity_label" ]
        add_field => { "alert_where" => "%{[nms][hostname]}" }
        add_field => { "alert_what" => "%{program}" }
        add_field => { "alert_message" => "*%{facility_label}.%{severity_label}*: %{message}" }
        add_field => { "alert_color" => "warning" }
      }
      if [event] {
        mutate {
          replace => { "alert_what" => "%{program}: %{event}" }
        }
      }
      if "EMERG" in [message] or [severity] < 3 {
        mutate {
          add_tag => [ "emerg" ]
          replace => { "alert_color" => "danger" }
        }
      }
    }

    if [trap] == "netflow_high_traffic" {
      mutate {
        add_field => { "alert_color" => "warning" }
        add_field => { "alert_where" => "%{[nms][hostname]}
zone %{[nms][zone]}" }
        add_field => { "alert_what" => "%{[nms][session]}
%{[netflow][in_bytes]} Bytes" }
      }
      if [nms][direction] == "inbound" {
        mutate { add_field => { "alert_message" => "*High Traffic!* %{[netflow][in_bytes]} Bytes comes from %{[nms][zone]} (%{[nms][session]}, %{[nms][direction]})" } }
      } else {
        mutate { add_field => { "alert_message" => "*High Traffic!* %{[netflow][in_bytes]} Bytes goes to %{[nms][zone]} (%{[nms][session]}, %{[nms][direction]})" } }
      }
    }
  }



  if "alert" == [type] {
    ruby {
      init => "require 'time'"
      code => "
        event['attachments'] = [{
          'color' => event['alert_color'],
          'fields' => [{
            'title' => 'Where', 'value' => event['alert_where'], 'short' => true
          }, {
            'title' => 'What', 'value' => event['alert_what'], short: true
          }],
          'fallback' => event['alert_message'],
          'pretext' => '$slack_pretext
>' + event['alert_message'],
          'title' => 'Hyeoncheon Elastic NMS Alert (' + event['origin'] + ')',
          'title_link' => 'https://github.com/hyeoncheon/hyeoncheon-elastic',
          'footer' => 'Hyeoncheon by scinix',
          'footer_icon' => 'http://hyeoncheon.github.io/images/hyeoncheon-icon.png',
          'ts' => Time.iso8601(event['@timestamp'].to_s).to_i,
          'mrkdwn_in' => [ 'text', 'pretext', 'fields' ]
        }]
      "
    }
  }
}

output {
  if "alert" == [type] {
    slack {
      url => "$slack_webhook"
      channel => "$slack_channel"
      username => "Hyeoncheon Elastic NMS"
      icon_emoji => "$slack_emoji"
      format => ""
    }
    stdout { codec => rubydebug { metadata => true } }
  }
}
EOF

