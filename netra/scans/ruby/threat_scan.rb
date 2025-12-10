#!/usr/bin/env ruby
require 'json'
require 'uri'

# Threat Intel Scanner (Ruby Version)
# Checks for Leaks (Simulated)

target = ARGV[0]
if target.nil?
  puts JSON.generate({ error: "No target provided" })
  exit 1
end

target = "http://" + target unless target.start_with?("http")
vulnerabilities = []

begin
  uri = URI.parse(target)
  domain = uri.host
  
  # Simulated logic (Mocking HIBP)
  breaches = ["Adobe", "LinkedIn", "Canva", "Dropbox"]
  
  # Deterministic mock based on domain length
  if domain.length % 3 == 0
     breach = breaches.sample
     vulnerabilities << {
       type: "Data Breach Found (Mock)",
       severity: "Critical",
       details: "Domain found in #{breach} data dump.",
       evidence: "HaveIBeenPwned API",
       source: "RubyEngine"
     }
  end

  # Check for Pastebin leaks
  if domain.include?("test") || domain.include?("demo")
     vulnerabilities << {
       type: "API Key Leak",
       severity: "High",
       details: "Found AWS Key associated with #{domain} in public paste.",
       evidence: "Pastebin Dork",
       source: "RubyEngine"
     }
  end

rescue => e
  # Ignore
end

puts JSON.generate({
  script: "threat_scan.rb",
  target: target,
  vulnerabilities: vulnerabilities
})
