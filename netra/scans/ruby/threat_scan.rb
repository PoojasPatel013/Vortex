#!/usr/bin/env ruby
require 'json'
require 'net/http'
require 'uri'
require 'resolv'

require 'ipaddr'

# Threat Intel Scanner (Ruby Version) - Logic Based
# Checks for SPF, DMARC, and Robots.txt (No API Keys)

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
  
  # Check if IP
  is_ip = false
  begin
    IPAddr.new(domain)
    is_ip = true
  rescue
    is_ip = false
  end
  
  # 1. DNS Checks (SPF & DMARC) - Skip for IPs
  unless is_ip
      dns = Resolv::DNS.new
      
      # SPF
      has_spf = false
      txt_records = dns.getresources(domain, Resolv::DNS::Resource::IN::TXT)
      txt_records.each do |rec|
         txt = rec.strings.join
         if txt.include?("v=spf1")
             has_spf = true
             if txt.include?("+all")
                 vulnerabilities << {
                     type: "Weak SPF Record",
                     severity: "High",
                     details: "SPF record uses +all (Authorizes entire internet).",
                     evidence: txt,
                     source: "RubyEngine"
                 }
             end
         end
      end
      
      unless has_spf
          vulnerabilities << {
             type: "Missing SPF Record",
             severity: "Medium",
             details: "No SPF record found to prevent email spoofing.",
             source: "RubyEngine"
          }
      end
      
      # DMARC
      has_dmarc = false
      dmarc_records = dns.getresources("_dmarc.#{domain}", Resolv::DNS::Resource::IN::TXT)
      dmarc_records.each do |rec|
          txt = rec.strings.join
          if txt.include?("v=DMARC1")
              has_dmarc = true
              if txt.include?("p=none")
                  vulnerabilities << {
                      type: "DMARC Policy Not Enforced",
                      severity: "Low",
                      details: "DMARC policy is 'p=none' (Monitoring only).",
                      evidence: txt,
                      source: "RubyEngine"
                  }
              end
          end
      end
      
      unless has_dmarc
         vulnerabilities << {
             type: "Missing DMARC Record",
             severity: "Medium",
             details: "No DMARC configuration found.",
             source: "RubyEngine"
         }
      end
  end
  
  # 2. Robots.txt Check
  robots_uri = URI.join(uri, "/robots.txt")
  http = Net::HTTP.new(robots_uri.host, robots_uri.port)
  http.use_ssl = (robots_uri.scheme == "https")
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE # Scan without validation
  
  req = Net::HTTP::Get.new(robots_uri.request_uri)
  res = http.request(req)
  
  if res.code == "200"
      sensitive_paths = ["admin", "backup", "db", "config", "debug"]
      detected = []
      res.body.each_line do |line|
          if line.downcase.start_with?("disallow:")
              path = line.split(":", 2)[1].strip
              if sensitive_paths.any? { |s| path.downcase.include?(s) }
                  detected << path
              end
          end
      end
      
      if detected.any?
          vulnerabilities << {
               type: "Sensitive Paths in Robots.txt",
               severity: "Low",
               details: "Disallowed paths reveal internal structure.",
               evidence: detected.take(3).join(", "),
               source: "RubyEngine"
          }
      end
  end

rescue => e
  # DNS or HTTP errors ignored
end

puts JSON.generate({
  script: "threat_scan.rb",
  target: target,
  vulnerabilities: vulnerabilities
})
