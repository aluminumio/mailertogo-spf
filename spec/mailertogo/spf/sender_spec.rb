# frozen_string_literal: true

RSpec.describe MailerToGo::SPF::Sender do
  it "treats every one of its names as itself" do
    sender = described_class.new("_spf.mailertogo.net", aliases: ["MailerToGo.net."])

    expect(sender.include_name).to eq("_spf.mailertogo.net")
    expect(sender.names).to eq(["_spf.mailertogo.net", "mailertogo.net"])
    expect(sender.covers?("MailerToGo.NET")).to be(true)
    expect(sender.covers?("notmailertogo.net")).to be(false)
  end

  it "builds the standalone record it wants published" do
    sender = described_class.new("_spf.mailertogo.net")

    expect(sender.record).to eq("v=spf1 include:_spf.mailertogo.net ~all")
    expect(sender.record(all: "-all")).to eq("v=spf1 include:_spf.mailertogo.net -all")
  end

  it "refuses to exist without a name" do
    expect { described_class.new("  ") }.to raise_error(ArgumentError)
  end

  describe "the module defaults" do
    it "answers for MailerToGo out of the box" do
      sender = MailerToGo::SPF.sender

      expect(sender.include_name).to eq("_spf.mailertogo.net")
      expect(sender.covers?("mailertogo.net")).to be(true)
    end

    it "does not lend our aliases to somebody else's include" do
      sender = MailerToGo::SPF.sender(include: "spf.example.net")

      expect(sender.names).to eq(["spf.example.net"])
    end
  end
end
