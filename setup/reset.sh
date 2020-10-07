#!/bin/bash

sudo systemctl stop logstash.service

if false; then
  echo "CLEANING EXISTING INDICES......"
  sleep 5
  for day in 14; do
    for index in logstash syslog netflow snmp; do
      curl -XDELETE localhost:9200/$index-2017.06.$day
    done
  done
fi

#./01-install-singlemode.sh
#./02-install-plugins.sh
#sleep 10

#./10-remote-syslog.sh
#./20-netflow.sh
#./30-snmp.sh
#./80-alert.sh

./restart.sh
