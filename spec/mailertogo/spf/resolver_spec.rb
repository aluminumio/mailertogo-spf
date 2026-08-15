# frozen_string_literal: true

# No example here touches the network: the point of the resolver seam is that it
# can be replaced, so these replace it.
RSpec.describe MailerToGo::SPF::CachingResolver do
  it "asks the underlying resolver once per name within the TTL" do
    inner = CountingResolver.new("example.com" => ["v=spf1 ~all"])
    caching = described_class.new(inner, ttl: 60)

    3.times { expect(caching.call("Example.com.")).to eq(["v=spf1 ~all"]) }

    expect(inner.calls).to eq(1)
  end

  it "asks again once the TTL has passed" do
    inner = CountingResolver.new("example.com" => ["v=spf1 ~all"])
    now = 0.0
    caching = described_class.new(inner, ttl: 60, clock: -> { now })

    caching.call("example.com")
    now = 61.0
    caching.call("example.com")

    expect(inner.calls).to eq(2)
  end

  # Caching a timeout would pin a healthy domain into :unknown for the whole
  # TTL, which is exactly the failure mode the nil return exists to avoid.
  it "never caches a DNS failure" do
    inner = CountingResolver.new("example.com" => nil)
    caching = described_class.new(inner, ttl: 60)

    2.times { expect(caching.call("example.com")).to be_nil }

    expect(inner.calls).to eq(2)
  end
end

RSpec.describe MailerToGo::SPF::Resolver do
  it "answers an empty name without going anywhere near DNS" do
    expect(described_class.new.call("")).to eq([])
  end

  # The whole contract, restated as an example so it cannot rot: a lambda is a
  # resolver.
  it "is interchangeable with any callable" do
    zone = { "example.com" => ["v=spf1 include:_spf.mailertogo.net ~all"] }
    result = MailerToGo::SPF.authorize("example.com", resolver: ->(n) { zone.fetch(n, []) })

    expect(result.pass?).to be(true)
  end
end
