# frozen_string_literal: true

require "ipaddr"

RSpec.describe MailerToGo::SPF::Macro do
  # The examples are RFC 7208 §7.4's own: connecting address 192.0.2.3, current
  # domain email.example.com.
  def expand(spec, address: "192.0.2.3")
    described_class.expand(spec, address: IPAddr.new(address), domain: "email.example.com",
                                 sender_domain: "example.com")
  end

  it "expands the RFC's examples it has the information for" do
    expect(expand("%{d}")).to eq("email.example.com")
    expect(expand("%{d4}")).to eq("email.example.com")
    expect(expand("%{d3}")).to eq("email.example.com")
    expect(expand("%{d2}")).to eq("example.com")
    expect(expand("%{d1}")).to eq("com")
    expect(expand("%{dr}")).to eq("com.example.email")
    expect(expand("%{d2r}")).to eq("example.email")
    expect(expand("%{ir}.%{v}._spf.%{d2}")).to eq("3.2.0.192.in-addr._spf.example.com")
    expect(expand("%{o}")).to eq("example.com")
  end

  it "expands an IPv6 address as dot-separated nibbles" do
    expect(expand("%{ir}.%{v}._spf.%{d2}", address: "2001:db8::cb01"))
      .to eq("1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.example.com")
  end

  it "splits on the delimiters a macro names" do
    expect(described_class.expand("%{dr-.}", address: IPAddr.new("192.0.2.3"), domain: "a-b.c",
                                             sender_domain: "x")).to eq("c.b.a")
  end

  it "returns nil for a macro that needs a message, a zero digit, or a bare %" do
    expect(expand("%{s}")).to be_nil
    expect(expand("%{i}.%{l}.example.com")).to be_nil
    expect(expand("%{h}")).to be_nil
    expect(expand("%{d0}")).to be_nil
    expect(expand("100%.example.com")).to be_nil
  end

  it "truncates an expansion past 253 characters from the left (§7.3)" do
    name = expand("%{i}.%{i}.%{i}.%{i}.#{"x" * 63}.#{"y" * 63}.#{"z" * 63}.example.com", address: "2001:db8::1")

    expect(name.length).to be <= 253
    expect(name).to end_with(".example.com")
  end

  it "knows which specs depend on the connecting address" do
    expect(described_class.per_address?("%{ir}.%{v}.example.com")).to be(true)
    expect(described_class.per_address?("%{d}.example.com")).to be(false)
  end
end
