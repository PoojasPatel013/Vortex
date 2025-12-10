#!/usr/bin/env ruby
require 'json'
require 'socket'
require 'timeout'
require 'uri'

# Slowloris Vulnerability Checker
# Checks if the server keeps connections open for partial requests.
# This indicates susceptibility to DoS/Crash attacks.

target_raw = ARGV[0]
if target_raw.nil?
  puts JSON.generate({ error: "No target provided" })
  exit 1
end

# Extract hostname
if target_raw.include?("://")
  target_host = URI.parse(target_raw).host
else
  target_host = target_raw
end

vulnerabilities = []

begin
  # Timeout check: If we can hold a socket for 5 seconds, it might be vulnerable.
  Timeout.timeout(7) do
    s = TCPSocket.new(target_host, 80)
    
    # Send partial header
    s.write("GET / HTTP/1.0\r\n")
    s.write("Host: #{target_host}\r\n")
    s.write("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n")
    s.write("Content-Length: 42\r\n")
    # We DO NOT send the final \r\n\r\n
    
    # Wait to see if server closes connection
    sleep 5
    
    # If we are here, the server kept it open.
    header_check = s.write("X-a: b\r\n") # Send keep-alive byte
    
    if header_check > 0
       vulnerabilities << {
          type: "DoS Susceptibility (Slowloris)",
          severity: "High",
          details: "Server accepted incomplete HTTP headers for > 5 seconds. Vulnerable to Slowloris DoS attacks that can crash the website.",
          evidence: "Socket held open for 5s with partial request.",
          source: "RubyEngine"
        }
    end
    s.close
  end
rescue Timeout::Error
  # Timed out implies it might be hanging (which is what we tested for) or network lag.
rescue Errno::ECONNRESET, Errno::EPIPE
  # Server closed connection - Good! Secure against Slowloris.
rescue => e
  # Connection failed
end

puts JSON.generate({
  script: "dos_check.rb",
  target: target_host,
  vulnerabilities: vulnerabilities
})
