#!/bin/bash

sudo systemctl restart elasticsearch.service
sudo systemctl restart logstash.service
sudo systemctl restart kibana.service
