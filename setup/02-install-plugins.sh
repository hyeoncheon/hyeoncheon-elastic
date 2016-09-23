#!/bin/bash
#

[ -f defaults.conf ] && . defaults.conf
[ -f env.conf ] && . env.conf

# install translate plugin
/opt/logstash/bin/logstash-plugin list | grep -q logstash-filter-translate || \
	sudo /opt/logstash/bin/logstash-plugin install logstash-filter-translate

# install slack out plugin
/opt/logstash/bin/logstash-plugin list | grep -q logstash-output-slack || \
	sudo /opt/logstash/bin/logstash-plugin install logstash-output-slack

