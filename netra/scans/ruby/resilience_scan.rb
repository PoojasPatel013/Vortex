#!/usr/bin/env ruby
require 'json'
require 'net/http'
require 'uri'
require 'openssl'

# Resilience Scanner (Ruby Version)
# Checks for Rate Limiting

target = ARGV[0]
if target.nil?
  puts JSON.generate({ error: "No target provided" })
  exit 1
end

target = "http://" + target unless target.start_with?("http")
vulnerabilities = []

begin
  uri = URI.parse(target)
  http = Net::HTTP.new(uri.host, uri.port)
  http.use_ssl = (uri.scheme == "https")
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  http.open_timeout = 5
  http.read_timeout = 5
  
  # Send 30 requests rapidly
  statuses = []
  30.times do
      req = Net::HTTP::Get.new(uri.request_uri)
      res = http.request(req)
      statuses << res.code.to_i
      # Short sleep to not completely choke self
      sleep(0.05) 
  end
  
  has_429 = statuses.include?(429)
  count_200 = statuses.count(200)
  
  if has_429
     # Good, rate limit detected
  elsif count_200 > 25
      vulnerabilities << {
        type: "Missing Rate Limiting",
        severity: "Medium",
        details: "Sent 30 requests rapidly and none were blocked (All 200 OK).",
        evidence: "Status Codes: #{statuses.uniq.join(',')}",
        source: "RubyEngine"
      }
  end

rescue => e
  # Ignore
end

puts JSON.generate({
  script: "resilience_scan.rb",
  target: target,
  vulnerabilities: vulnerabilities
})
