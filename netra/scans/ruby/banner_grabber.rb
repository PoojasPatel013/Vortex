#!/usr/bin/env ruby
require 'json'
require 'socket'
require 'timeout'
require 'uri'

# Real TCP Banner Grabber
# Connects to common ports to "grab banners" (service identification).
# No mock data. Real TCP sockets.

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

PORTS = {
  21 => "FTP",
  22 => "SSH",
  23 => "Telnet",
  25 => "SMTP",
  80 => "HTTP",
  443 => "HTTPS",
  8080 => "HTTP-Alt",
  3306 => "MySQL",
  5432 => "PostgreSQL"
}

vulnerabilities = []

PORTS.each do |port, service|
  begin
    Timeout.timeout(2) do
      s = TCPSocket.new(target_host, port)
      
      # For some protocols, we might need to send data to get a banner
      if [80, 443, 8080].include?(port)
        s.write("HEAD / HTTP/1.0\r\n\r\n")
      end
      
      banner = s.recv(1024).strip
      s.close
      
      if !banner.empty?
        # Clean banner
        banner = banner.gsub(/[^\x20-\x7E]/, '') # Keep printable
        
        vulnerabilities << {
          type: "Service Banner Exposed",
          severity: "Low",
          details: "Port #{port} (#{service}) exposed banner: #{banner[0..50]}...",
          evidence: banner,
          source: "RubyEngine"
        }
        
        # Check for specific "Hack" opportunities (Real version checking)
        if banner.downcase.include?("openssh")
          vulnerabilities << {
             type: "OpenSSH Detected",
             severity: "Info",
             details: "Found OpenSSH service. Version extraction possible for CVE checks.",
             evidence: banner,
             source: "RubyEngine"
          }
        end
      end
    end
  rescue Timeout::Error, Errno::ECONNREFUSED, Errno::EHOSTUNREACH, SocketError => e
    # Port closed or unreachable, just ignore
  rescue StandardError => e
    # Ignore other errors
  end
end

result = {
  script: "banner_grabber.rb",
  target: target_host,
  vulnerabilities: vulnerabilities
}

puts JSON.generate(result)
