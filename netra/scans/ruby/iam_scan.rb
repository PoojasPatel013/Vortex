#!/usr/bin/env ruby
require 'json'
require 'net/http'
require 'uri'
require 'openssl'

# IAM & Session Scanner (Ruby Version)
# Checks for Weak Cookies and Missing Headers

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
  http.open_timeout = 10
  http.read_timeout = 10
  
  request = Net::HTTP::Get.new(uri.request_uri)
  response = http.request(request)
  
  # 1. Analyze Set-Cookie Headers
  cookies = response.get_fields('set-cookie')
  if cookies
    cookies.each do |cookie|
      issues = []
      
      # Check flags
      unless cookie.downcase.include?("secure")
        # Only flag missing secure if target is https, or generally weak guidance
        issues << "Missing Secure Flag" if uri.scheme == "https"
      end
      
      unless cookie.downcase.include?("httponly")
        issues << "Missing HttpOnly Flag"
      end
      
      unless cookie.downcase.include?("samesite")
        issues << "Missing SameSite Attribute"
      end
      
      # Check Entropy (Simple Length Heuristic for Ruby MVP)
      # Extract value: SESSIONID=12345; path=/
      if cookie =~ /=(.*?);/
          val = $1
          if val && val.length < 8
              issues << "Weak Cookie Entropy (Too Short)"
          end
      end

      if issues.any?
        vulnerabilities << {
          type: "Weak Session Cookie",
          severity: "Medium",
          details: "Issues found in cookie: #{issues.join(', ')}",
          evidence: cookie,
          source: "RubyEngine"
        }
      end
    end
  end
  
  # 2. Check for Basic Auth
  if response['www-authenticate']
     vulnerabilities << {
        type: "Basic Authentication Detected",
        severity: "Low",
        details: "Server requests Basic Auth. Ensure this is over HTTPS.",
        evidence: response['www-authenticate'],
        source: "RubyEngine"
     }
  end

rescue => e
  # Return empty if connection fails
end

puts JSON.generate({
  script: "iam_scan.rb",
  target: target,
  vulnerabilities: vulnerabilities
})
