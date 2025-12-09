#!/usr/bin/env ruby
require 'json'
require 'socket'
require 'timeout'

# MQTT Auditor
# Checks for Open MQTT Brokers (IoT Vulnerability)

target = ARGV[0]
if target.nil?
  puts JSON.generate({ error: "No target provided" })
  exit 1
end

# Check standard MQTT port
port = 1883
vulnerabilities = []

begin
  Timeout.timeout(3) do
    s = TCPSocket.new(target, port)
    
    # MQTT Connect Packet (Anonymous)
    # Fixed header: 0x10 (Connect), Remaining Length: 12
    # Protocol Name Length: 4 (00 04), Protocol Name: MQTT
    # Protocol Level: 4 (04)
    # Connect Flags: 2 (Clean Session, No Auth)
    # Keep Alive: 60 (00 3C)
    # Client ID Length: 0 (00 00)
    packet = "\x10\x0C\x00\x04MQTT\x04\x02\x00\x3C\x00\x00"
    
    s.write(packet)
    response = s.recv(1024)
    s.close
    
    # Check ConnAck (0x20) and Return Code 0 (Accepted)
    if response.bytes.length >= 4 && response.bytes[0] == 0x20 && response.bytes[3] == 0x00
      vulnerabilities << {
        type: "Open MQTT Broker",
        severity: "Critical",
        details: "MQTT Broker on port 1883 accepts anonymous connections. This often exposes IoT device streams.",
        evidence: "Received ConnAck: Connection Accepted",
        source: "RubyEngine"
      }
    end
  end
rescue => e
  # Connection failed or timed out - likely closed
end

puts JSON.generate({
  script: "mqtt_audit.rb",
  target: target,
  vulnerabilities: vulnerabilities
})
