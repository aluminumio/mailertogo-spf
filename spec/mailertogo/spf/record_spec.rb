# frozen_string_literal: true

RSpec.describe MailerToGo::SPF::Record do
  describe ".include_target" do
    it "extracts the include mechanism from a record" do
      expect(described_class.include_target("v=spf1 include:_spf.mailertogo.net ~all"))
        .to eq("_spf.mailertogo.net")
    end

    it "is nil for a record with no include" do
      expect(described_class.include_target("v=spf1 ip4:203.0.113.4 ~all")).to be_nil
      expect(described_class.include_target("not an spf record")).to be_nil
    end
  end

  describe ".spf_record?" do
    it "accepts a record and rejects a lookalike version string" do
      expect(described_class.spf_record?("v=spf1 ~all")).to be(true)
      expect(described_class.spf_record?("v=spf1")).to be(true)
      expect(described_class.spf_record?("v=spf10 ~all")).to be(false)
      expect(described_class.spf_record?("v=DMARC1; p=none")).to be(false)
    end
  end

  describe ".normalize_txt" do
    # RFC 1035 §3.3.14 caps a character-string at 255 octets, so a long record
    # arrives in chunks; RFC 7208 §3.3 says to concatenate them with nothing
    # between.
    it "joins the character-strings of a chunked TXT answer" do
      expect(described_class.normalize_txt('"v=spf1 include:_spf.mailer" "togo.net ~all"'))
        .to eq("v=spf1 include:_spf.mailertogo.net ~all")
    end
  end

  describe ".normalize_name" do
    it "lowercases and drops the root dot" do
      expect(described_class.normalize_name(" MailerToGo.NET. ")).to eq("mailertogo.net")
    end
  end

  describe ".ip_nets" do
    it "reads ip4/ip6 terms and drops unparseable ones" do
      nets = described_class.ip_nets(%w[ip4:192.0.2.0/24 +ip6:2001:db8::/32 ip4:nonsense a mx])

      expect(nets.map(&:to_s)).to eq(["192.0.2.0", "2001:db8::"])
    end
  end
end
