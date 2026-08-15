# frozen_string_literal: true

require "mailertogo/spf"

RSpec.configure do |config|
  config.expect_with(:rspec) { |c| c.syntax = :expect }
  config.disable_monkey_patching!
  config.order = :random
  Kernel.srand config.seed
end

# The record we ask a domain with no SPF of its own to publish.
OUR_RECORD = "v=spf1 include:_spf.mailertogo.net ~all"

# Every example in this suite resolves DNS through a stubbed zone. Nothing here
# touches the network, and nothing here should ever need to.
module ZoneHelper
  # The sender's own published chain: an outer alias and the leaf that lists the
  # addresses. Addresses are RFC 5737 documentation ranges.
  SENDER_ZONE = {
    "mailertogo.net" => ["v=spf1 include:_spf.mailertogo.net ~all"],
    "_spf.mailertogo.net" => ["v=spf1 ip4:192.0.2.10 ip4:192.0.2.11 ip4:192.0.2.128/25 ~all"],
  }.freeze

  # Stub DNS: { name => [txt strings] }.
  #   a missing key      = the name publishes no TXT
  #   an explicit nil    = the resolver failed (timeout / SERVFAIL)
  def resolver_for(zone)
    merged = SENDER_ZONE.merge(zone)
    ->(name) { merged.key?(name) ? merged[name] : [] }
  end
end

RSpec.configure { |config| config.include ZoneHelper }

# A resolver that counts how often it is asked, for the caching examples.
class CountingResolver
  attr_reader :calls

  def initialize(answers)
    @answers = answers
    @calls = 0
  end

  def call(name)
    @calls += 1
    @answers.fetch(name, [])
  end
end
