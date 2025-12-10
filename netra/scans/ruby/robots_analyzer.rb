#!/usr/bin/env ruby
require 'json'
require 'net/http'
require 'uri'

# Real Robots.txt Analyzer for Vortex
# Fetches robots.txt and identifies sensitive 'Disallow' entries.
# This provides REAL dynamic feedback based on the target.

target = ARGV[0]
if target.nil?
  puts JSON.generate({ error: "No target provided" })
  exit 1
end

# Ensure protocol
target = "http://" + target unless target.start_with?("http")

begin
  uri = URI.parse(target)
  robots_uri = URI.join(uri, "/robots.txt")
  
  http = Net::HTTP.new(robots_uri.host, robots_uri.port)
  http.use_ssl = (robots_uri.scheme == "https")
  http.verify_mode = OpenSSL::SSL::VERIFY_NONE # For pentesters convenience
  http.open_timeout = 5
  http.read_timeout = 5
  
  request = Net::HTTP::Get.new(robots_uri.request_uri)
  response = http.request(request)
  
  result = {
    script: "robots_analyzer.rb",
    target: target,
    vulnerabilities: []
  }

  if response.code == '200'
    sensitive_paths = ['/admin', '/private', '/config', '/api', '/dashboard', '/db', '/backup']
    disallowed_entries = []
    
    response.body.each_line do |line|
      if line.match?(/^Disallow:/i)
        path = line.split(':')[1].strip
        disallowed_entries << path
        
        # Check if path is sensitive
        if sensitive_paths.any? { |s| path.downcase.include?(s) }
          result[:vulnerabilities] << {
            type: "Sensitive Robots.txt Entry",
            severity: "Medium",
            details: "Found sensitive path disallowed in robots.txt: #{path}",
            evidence: line.strip,
            source: "RubyEngine"
          }
        end
      end
    end
    
    # If no sensitive paths, still report we found robots.txt
    if result[:vulnerabilities].empty? && disallowed_entries.any?
        result[:vulnerabilities] << {
            type: "Robots.txt Found",
            severity: "Info",
            details: "Found robots.txt with #{disallowed_entries.count} disallow entries.",
            evidence: "First 3: #{disallowed_entries.take(3).join(', ')}",
            source: "RubyEngine"
        }
    end

  else
    # Only report if missing if we really want to be verbose, but let's keep it clean.
    # We don't report anything if robots.txt is missing to avoid noise.
  end

  puts JSON.generate(result)

rescue StandardError => e
  # Return empty vulns on error to not break pipeline
  puts JSON.generate({ 
    script: "robots_analyzer.rb",
    target: target,
    vulnerabilities: [],
    error: e.message 
  })
end
