# frozen_string_literal: true

require_relative "lib/mailertogo/spf/version"

Gem::Specification.new do |spec|
  spec.name = "mailertogo-spf"
  spec.version = MailerToGo::SPF::VERSION
  spec.authors = ["MailerToGo"]
  spec.email = ["support@mailertogo.com"]

  spec.summary = "Resolve SPF records the way a receiving MTA does, and plan the record a domain should publish."
  spec.description = <<~DESC
    An SPF engine that follows include:/redirect= chains, stops at the first
    matching mechanism, and counts DNS-querying terms against RFC 7208 §4.6.4's
    cap of 10 — so it agrees with what real receivers do instead of
    string-matching a token. It also plans the record a domain should publish:
    given what is already at the name, merge one include into the existing
    record rather than adding a second v=spf1 record beside it. No Rails, no
    runtime dependencies, injectable DNS resolver.
  DESC

  spec.homepage = "https://github.com/aluminumio/mailertogo-spf"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1.0"

  spec.metadata = {
    "source_code_uri" => spec.homepage,
    "changelog_uri" => "#{spec.homepage}/blob/main/CHANGELOG.md",
    "bug_tracker_uri" => "#{spec.homepage}/issues",
    "rubygems_mfa_required" => "true",
  }

  spec.files = Dir[
    "lib/**/*.rb",
    "README.md",
    "CHANGELOG.md",
    "LICENSE"
  ]
  spec.require_paths = ["lib"]
end
