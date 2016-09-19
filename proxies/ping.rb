#!/usr/bin/env ruby

require 'bundler/setup'
require 'net/ping'
require 'json'

shipper_addr = 'localhost'
shipper_port = 7450
collect_interval = 300

sock = UDPSocket.new
last = Time.now
while true
  conf = File.read('ping_targets.json')
  targets = JSON.parse(conf, :symbolize_names => true)

  targets.each do |target|
    t = Net::Ping::TCP.new(target[:addr], target[:port])

    sum = 0
    count = 0
    [1,2,3].each do
      if t.ping
        sum += t.duration
        count += 1
      end
    end
    target[:rtt_ms] = sum * 1000 / count
    target[:count] = count

    sock.send("#{target.to_json}\n", 0, shipper_addr, shipper_port)
    puts target.to_json
  end

  # timing
  now = Time.now
  _next = [last + collect_interval, now].max
  sleep (_next - now)
  last = _next
end
sock.close

