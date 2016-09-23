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
        add_field => { "origin" => "snmp" }
        clones => [ "alert" ]
      }
    }
  }


  if [type] == "alert" {
    if [trap] == "snmp_high_traffic" {
      ruby {
        code => "
          event['alert_what'] = 'RX ' + event['rx_bps'].round.to_s + ' B/s ' +
                                'TX ' + event['tx_bps'].round.to_s + ' B/s';
        "
      }
      mutate {
        add_field => { "alert_where" => "%{[nms][hostname]} zone %{[nms][zone]}" }
        add_field => { "alert_message" => "*High Traffic!* %{[nms][hostname]} port %{ifname}" }
        add_field => { "alert_color" => "danger" }
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
        add_field => { "alert_message" => "*Low Latency!* ping to %{ping_name}" }
        add_field => { "alert_color" => "warning" }
      }
    }

  }


  if "alert" == [type] {
    ruby {
      init => "require 'time'"
      code => "
        event['attachments'] = [{
          'color' => event['alert_color'],
          'text' => event['alert_message'],
          'fields' => [{
            'title' => 'Where', 'value' => event['alert_where'],
          }, {
            'title' => 'What', 'value' => event['alert_what'],
          }],
          'pretext' => '$slack_pretext',
          'title' => 'Hyeoncheon NMS Alert (' + event['origin'] + ')',
          'title_link' => 'https://github.com/hyeoncheon/hyeoncheon-elastic',
          'author_name' => 'Hyeoncheon Elastic NMS',
          'author_link' => 'https://github.com/hyeoncheon/hyeoncheon-elastic',
          'author_icon' => 'http://hyeoncheon.github.io/images/hyeoncheon-icon.png',
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
      username => "Hyeoncheon NMS Alert"
      icon_emoji => "$slack_emoji"
      format => ""
    }
    stdout { codec => rubydebug { metadata => true } }
  }
}
EOF

