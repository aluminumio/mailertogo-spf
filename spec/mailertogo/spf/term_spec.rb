# frozen_string_literal: true

RSpec.describe MailerToGo::SPF::Term do
  def term(raw, **opts) = described_class.new(raw: raw, **opts)

  describe "what a term is" do
    it "reads a mechanism, its qualifier and its target" do
      t = term("-include:_spf.mailertogo.net")

      expect(t.mechanism).to eq("include")
      expect(t.qualifier).to eq("-")
      expect(t.qualifier_meaning).to eq(:fail)
      expect(t.target).to eq("_spf.mailertogo.net")
      expect(t).to be_include
      expect(t.kind).to eq("include")
    end

    it "defaults an absent qualifier to + (§4.6.2)" do
      expect(term("include:_spf.mailertogo.net").qualifier).to be_nil
      expect(term("include:_spf.mailertogo.net").qualifier_meaning).to eq(:pass)
    end

    it "has no target for a bare a, mx or all" do
      expect(term("a").target).to be_nil
      expect(term("mx").target).to be_nil
      expect(term("~all").target).to be_nil
    end

    it "reads a modifier as a modifier, not a mechanism" do
      t = term("redirect=other.example.net")

      expect(t.modifier).to eq("redirect")
      expect(t.mechanism).to be_nil
      expect(t.target).to eq("other.example.net")
      expect(t).to be_redirect
      expect(t.kind).to eq("modifier")
    end

    it "knows which terms spend from the §4.6.4 budget" do
      querying = ["include:x.example.net", "a", "mx", "ptr", "exists:%{i}.example.net",
                  "redirect=other.example.net",]
      free = ["ip4:198.51.100.7", "ip6:2001:db8::/32", "~all", "exp=why.example.net"]

      expect(querying.map { |r| term(r).querying? }).to all(be(true))
      expect(free.map { |r| term(r).querying? }).to all(be(false))
    end

    it "flags junk as unknown rather than letting it look harmless" do
      t = term("include_spf.mailertogo.net")

      expect(t).to be_unknown
      expect(t.mechanism).to be_nil
      expect(t.modifier).to be_nil
      expect(t.kind).to eq("unknown")
    end
  end

  # The case worth having a regex for. A record ending
  # `~all;google-site-verification=…` is real and not rare: the `;`-joined
  # fragment is not a valid SPF term, and reading the whole thing as junk would
  # lose the record's terminal `all` — and with it the domain's entire policy
  # for unauthorised mail.
  describe "junk glued onto `all`" do
    subject(:t) { term("~all;google-site-verification=abc123") }

    it "is still a terminal all, with its qualifier intact" do
      expect(t).to be_all
      expect(t.mechanism).to eq("all")
      expect(t.qualifier).to eq("~")
      expect(t.qualifier_meaning).to eq(:softfail)
    end

    it "surfaces the junk separately" do
      expect(t.all_suffix).to eq(";google-site-verification=abc123")
      expect(term("~all").all_suffix).to be_nil
    end

    it "does not mistake a name that merely starts with all for the mechanism" do
      expect(term("allow.example.net")).not_to be_all
      expect(term("include:all.example.net")).not_to be_all
    end
  end

  describe "pricing" do
    it "builds a priced copy rather than mutating, so a term is never half-priced" do
      t = term("include:_spf.mailertogo.net", position: 2)
      priced = t.priced(lookups: 3, running_total: 4)

      expect(t.lookups).to be_nil
      expect(priced.lookups).to eq(3)
      expect(priced.running_total).to eq(4)
      expect(priced.position).to eq(2)
      expect(priced).to be_frozen
    end

    it "keeps a subclass through pricing, so a caller's copy survives the audit" do
      annotated = Class.new(described_class)
      priced = annotated.new(raw: "~all").priced(lookups: 0, running_total: 0)

      expect(priced).to be_a(annotated)
    end
  end

  describe "Record.parse_terms" do
    it "numbers the terms of a record from 1, in record order" do
      terms = MailerToGo::SPF::Record.parse_terms("v=spf1 include:_spf.mailertogo.net ip4:198.51.100.7 ~all")

      expect(terms.map(&:raw)).to eq(["include:_spf.mailertogo.net", "ip4:198.51.100.7", "~all"])
      expect(terms.map(&:position)).to eq([1, 2, 3])
      expect(terms.map(&:kind)).to eq(%w[include ip4 all])
    end

    it "builds the caller's Term subclass" do
      annotated = Class.new(described_class)
      terms = MailerToGo::SPF::Record.parse_terms("v=spf1 ~all", term_class: annotated)

      expect(terms.first).to be_a(annotated)
    end
  end
end
