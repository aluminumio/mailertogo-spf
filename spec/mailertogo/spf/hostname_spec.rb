# frozen_string_literal: true

# The gate in front of anything that resolves DNS on untrusted input.
# Forgiving about what people paste, strict about what reaches a resolver.
RSpec.describe MailerToGo::SPF::Hostname do
  describe ".parse" do
    it "accepts a plain hostname" do
      expect(described_class.parse("example.com")).to eq("example.com")
    end

    it "normalises case and the optional root dot" do
      expect(described_class.parse("  WWW.Example.COM.  ")).to eq("www.example.com")
    end

    it "pulls the host out of a pasted URL" do
      expect(described_class.parse("https://www.example.com/pricing?x=1#top")).to eq("www.example.com")
    end

    it "pulls the domain out of a pasted email address" do
      expect(described_class.parse("billing@example.com")).to eq("example.com")
    end

    it "accepts underscore labels, because SPF names are worth checking" do
      expect(described_class.parse("_spf.mailertogo.net")).to eq("_spf.mailertogo.net")
    end

    it "never honours a supplied port" do
      expect(described_class.parse("example.com:5353")).to eq("example.com")
    end

    it "rejects junk" do
      ["", "   ", "v=spf1", "not a domain", "example", "..", "a..b", "-example.com", "example.com-",
       "1.2.3.4", "192.168.0.1", "example.1", "exämple.com", "[::1]", "a" * 300,].each do |input|
        expect(described_class.parse(input)).to be_nil, "expected #{input.inspect} to be rejected"
      end
    end

    it "rejects a label longer than DNS allows" do
      expect(described_class.parse("#{"a" * 64}.com")).to be_nil
    end
  end

  describe ".valid?" do
    it "mirrors parse" do
      expect(described_class).to be_valid("example.com")
      expect(described_class).not_to be_valid("v=spf1")
    end
  end

  describe "the module-level entry points" do
    it "reads the same as the module they delegate to" do
      expect(MailerToGo::SPF.normalize_hostname("HTTPS://Example.com/x")).to eq("example.com")
      expect(MailerToGo::SPF.hostname?("example.com")).to be(true)
      expect(MailerToGo::SPF.hostname?("v=spf1")).to be(false)
    end
  end
end
