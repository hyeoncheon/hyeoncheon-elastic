#!/usr/bin/env ruby

require 'bundler/setup'
require 'snmp'
require 'json'

device = ARGV[0]
if device
  puts "collect SNMP interface statistics for #{device}..."
else
  puts "usage: #{$PROGRAM_NAME} IP_ADDR"
  exit
end

shipper_addr = 'localhost'
shipper_port = 7450
collect_interval = 60


ifTable_columns = [ "ifIndex", "ifName", "ifInOctets", "ifOutOctets", "ifSpeed", "ifOperStatus" ]

def c32diff(curr, prev)
  if curr >= prev
    return curr - prev
  else
    return 2**32 - prev + curr
  end
end

sock = UDPSocket.new
last = Time.now
store = {}
while true
  SNMP::Manager.open(:Host => device) do |manager|
    now = Time.now
    manager.walk(ifTable_columns) do |idx, name, inoctets, outoctets, spd, os|
      if os.value == 1 and name.value != "lo"
        data = { :device => device, :timestamp => now.iso8601 }
        data[:ifindex] = idx.value.to_i
        data[:ifname] = name.value.to_s
        data[:ifinoctets] = inoctets.value.to_i
        data[:ifoutoctets] = outoctets.value.to_i
        data[:ifspeed] = spd.value.to_i

        # work-around for derivative aggregation.
        prev = store["d#{idx.value}"]
        if prev
          t_gap = now - Time.iso8601(prev[:timestamp])
          rx_diff = c32diff(data[:ifinoctets], prev[:ifinoctets])
          tx_diff = c32diff(data[:ifoutoctets], prev[:ifoutoctets])
          data[:rx_bps] = rx_diff / t_gap
          data[:tx_bps] = tx_diff / t_gap
        else
          data[:rx_bps] = 0
          data[:tx_bps] = 0
        end
        store["d#{idx.value}"] = data

        sock.send("#{data.to_json}\n", 0, shipper_addr, shipper_port)
        puts "#{data.to_json}"
      end
    end
  end

  now = Time.now
  _next = [last + collect_interval, now].max
  sleep (_next - now)
  last = _next
end
sock.close


# RFC1213-MIB::ifIndex.279 = INTEGER: 279
# RFC1213-MIB::ifDescr.279 = STRING: "vti0"
# RFC1213-MIB::ifType.279 = INTEGER: 131
# RFC1213-MIB::ifMtu.279 = INTEGER: 1500
# RFC1213-MIB::ifSpeed.279 = Gauge32: 0
# RFC1213-MIB::ifPhysAddress.279 = Hex-STRING: A1 CA 26 5A 00 00 
# RFC1213-MIB::ifAdminStatus.279 = INTEGER: up(1)
# RFC1213-MIB::ifOperStatus.279 = INTEGER: up(1)
# RFC1213-MIB::ifLastChange.279 = Timeticks: (59713276) 6 days, 21:52:12.76
# RFC1213-MIB::ifInOctets.279 = Counter32: 399953671
# RFC1213-MIB::ifInUcastPkts.279 = Counter32: 23435792
# RFC1213-MIB::ifInNUcastPkts.279 = Counter32: 0
# RFC1213-MIB::ifInDiscards.279 = Counter32: 0
# RFC1213-MIB::ifInErrors.279 = Counter32: 0
# RFC1213-MIB::ifInUnknownProtos.279 = Counter32: 0
# RFC1213-MIB::ifOutOctets.279 = Counter32: 74422389
# RFC1213-MIB::ifOutUcastPkts.279 = Counter32: 16696902
# RFC1213-MIB::ifOutNUcastPkts.279 = Counter32: 0
# RFC1213-MIB::ifOutDiscards.279 = Counter32: 0
# RFC1213-MIB::ifOutErrors.279 = Counter32: 9325
# RFC1213-MIB::ifOutQLen.279 = Gauge32: 0
# RFC1213-MIB::ifSpecific.279 = OID: SNMPv2-SMI::zeroDotZero
