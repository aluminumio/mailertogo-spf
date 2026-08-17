# frozen_string_literal: true

RSpec.describe MailerToGo::SPF::ChainAudit do
  def audit(zone, record: nil, host: "example.com")
    MailerToGo::SPF.chain_audit(host, record: record, resolver: resolver_for(zone))
  end

  describe "pricing the whole tree" do
    let(:google) do
      {
        "example.com" => ["v=spf1 include:_spf.google.com ip4:198.51.100.7 ~all"],
        "_spf.google.com" => ["v=spf1 include:_netblocks.google.com include:_netblocks2.google.com ~all"],
        "_netblocks.google.com" => ["v=spf1 ip4:35.190.247.0/24 ~all"],
        "_netblocks2.google.com" => ["v=spf1 ip6:2001:4860:4000::/36 ~all"],
      }
    end

    it "charges an include for everything its record pulls in, not just itself" do
      a = audit(google)

      expect(a).to be_published
      expect(a.total).to eq(3)
      expect(a).not_to be_over_limit
      expect(a.headroom).to eq(7)
    end

    it "attaches the cost to the term that incurred it, with a running total" do
      terms = audit(google).terms

      expect(terms.map(&:raw)).to eq(["include:_spf.google.com", "ip4:198.51.100.7", "~all"])
      expect(terms.map(&:lookups)).to eq([3, 0, 0])
      expect(terms.map(&:running_total)).to eq([3, 3, 3])
      expect(terms.map(&:position)).to eq([1, 2, 3])
    end

    it "charges a / mx / ptr / exists one lookup each and expands no further" do
      a = audit({ "example.com" => ["v=spf1 a mx ptr exists:%{i}.example.net ip4:198.51.100.7 ~all"] })

      expect(a.terms.map(&:lookups)).to eq([1, 1, 1, 1, 0, 0])
      expect(a.total).to eq(4)
    end

    it "prices a record that is not published yet" do
      a = audit({ "spf.partner.example" => ["v=spf1 ip4:198.51.100.0/24 ~all"] },
                record: "v=spf1 include:spf.partner.example include:_spf.mailertogo.net ~all")

      expect(a.total).to eq(2)
      expect(a.headroom).to eq(8)
    end
  end

  # The reason this class exists next to Authorization. Both numbers are right;
  # they answer different questions, and a page that reports only the first is
  # telling the domain owner their record is fine when it is broken for
  # everybody listed after us.
  describe "a record over the cap whose match lands inside it" do
    subject(:zone) do
      providers = (1..8).to_h { |i| ["p#{i}.example.net", ["v=spf1 ip4:203.0.113.#{i} ~all"]] }
      { "example.com" => ["v=spf1 #{(1..8).map { |i| "include:p#{i}.example.net" }.join(" ")} " \
                          "include:relay.example.net include:_spf.mailertogo.net ~all"],
        "relay.example.net" => ["v=spf1 include:_spf.mailertogo.net ~all"], }.merge(providers)
    end

    it "prices the whole record at 11 where the authorization walk spends 10" do
      expect(audit(zone).total).to eq(11)
      expect(audit(zone)).to be_over_limit

      # §4.6.2 — the receiver stops at our include, so the gating answer is
      # "passes, at a cost of 10". Both are true.
      verdict = MailerToGo::SPF.authorize("example.com", resolver: resolver_for(zone))
      expect(verdict).to be_pass
      expect(verdict.lookups).to eq(10)
    end
  end

  describe "the §4.6.4 cap" do
    it "counts past it — 10 is legal, 11 permerrors" do
      providers = (1..11).to_h { |i| ["p#{i}.example.net", ["v=spf1 ip4:203.0.113.#{i} ~all"]] }
      a = audit({ "example.com" => ["v=spf1 #{(1..11).map { |i| "include:p#{i}.example.net" }.join(" ")} -all"] }
                  .merge(providers))

      expect(a.total).to eq(11)
      expect(a).to be_over_limit
      expect(a.limit).to eq(10)
      expect(a.headroom).to eq(0)
    end

    it "stops resolving past the ceiling and reports the total as a floor" do
      # A record that fans out far past the cap. Once it is this broken the
      # exact number no longer changes what anyone should do about it, so we
      # stop resolving rather than chase it.
      zone = { "example.com" => ["v=spf1 #{(1..3).map { |i| "include:a#{i}.example.net" }.join(" ")} -all"] }
      (1..3).each do |i|
        zone["a#{i}.example.net"] = ["v=spf1 #{(1..10).map { |j| "include:b#{i}-#{j}.example.net" }.join(" ")} ~all"]
        (1..10).each { |j| zone["b#{i}-#{j}.example.net"] = ["v=spf1 ip4:203.0.113.#{j} ~all"] }
      end

      a = audit(zone)

      expect(a).to be_capped
      expect(a).to be_over_limit
      expect(a.headroom).to be_nil # a floor cannot answer "how much room is left"
    end
  end

  describe "terms a receiver never evaluates" do
    it "marks a term stranded after `all` unreachable and charges it nothing" do
      a = audit({ "example.com" => ["v=spf1 ip4:198.51.100.7 ~all include:_spf.mailertogo.net"] })

      stranded = a.terms.last
      expect(stranded).to be_unreachable
      expect(stranded.lookups).to eq(0)
      expect(a.total).to eq(0)
    end

    # §6.1 — a record containing `all` ignores its redirect= outright, wherever
    # in the record the redirect sits, so the redirect costs nothing.
    it "charges nothing for a redirect= in a record that has an `all`" do
      a = audit({ "example.com" => ["v=spf1 redirect=other.example.net ~all"],
                  "other.example.net" => ["v=spf1 include:p1.example.net ~all"],
                  "p1.example.net" => ["v=spf1 ip4:203.0.113.1 ~all"], })

      expect(a.terms.first).to be_unreachable
      expect(a.total).to eq(0)
    end

    it "follows a redirect= when there is no `all` to override it" do
      a = audit({ "example.com" => ["v=spf1 redirect=other.example.net"],
                  "other.example.net" => ["v=spf1 include:p1.example.net ~all"],
                  "p1.example.net" => ["v=spf1 ip4:203.0.113.1 ~all"], })

      expect(a.terms.first).not_to be_unreachable
      expect(a.total).to eq(2)
    end
  end

  describe "defects found on the way" do
    # §5.2 — an include: of a name with no v=spf1 record is a permerror for the
    # whole evaluation, not a term that quietly does nothing.
    it "names an include target that publishes no SPF, and still charges the lookup" do
      a = audit({ "example.com" => ["v=spf1 include:nothing.example.net ~all"] })

      expect(a.targets_without_spf).to eq(["nothing.example.net"])
      expect(a.total).to eq(1)
    end

    # §4.5 — two records anywhere in the chain permerror the whole evaluation,
    # even though the duplicate is in somebody else's record.
    it "names a chain member that publishes more than one record" do
      a = audit({ "example.com" => ["v=spf1 include:two.example.net ~all"],
                  "two.example.net" => ["v=spf1 ip4:203.0.113.1 ~all", "v=spf1 ip4:203.0.113.2 ~all"], })

      expect(a.duplicated_in_chain).to eq(["two.example.net"])
    end

    it "names the apex itself when it is the one publishing two records" do
      a = audit({ "example.com" => ["v=spf1 ip4:203.0.113.1 ~all", "v=spf1 ip4:203.0.113.2 ~all"] })

      expect(a.duplicated_in_chain).to eq(["example.com"])
    end

    it "does not walk a record that includes itself" do
      a = audit({ "example.com" => ["v=spf1 include:example.com ~all"] })

      expect(a.total).to eq(1)
    end

    it "charges a macro term but does not follow it" do
      a = audit({ "example.com" => ["v=spf1 include:%{i}.example.net ~all"] })

      expect(a.total).to eq(1)
      expect(a.targets_without_spf).to be_empty
    end
  end

  describe "when DNS does not answer" do
    it "reports the total as a floor rather than claiming the record fits" do
      a = audit({ "example.com" => ["v=spf1 include:down.example.net include:p1.example.net ~all"],
                  "down.example.net" => nil,
                  "p1.example.net" => ["v=spf1 ip4:203.0.113.1 ~all"], })

      expect(a).to be_partial
      expect(a.total).to eq(2)
      expect(a.headroom).to be_nil
    end

    it "does not read a resolver failure at the apex as `no SPF here`" do
      a = audit({ "example.com" => nil })

      expect(a).not_to be_resolved
      expect(a).not_to be_published
      expect(a).to be_partial
      expect(a.terms).to be_empty
    end

    it "is unpublished, not broken, when the name simply has no SPF" do
      a = audit({})

      expect(a).to be_resolved
      expect(a).not_to be_published
      expect(a.total).to eq(0)
    end
  end

  # The seam a consumer uses to hang its own copy off a term without standing up
  # a second parser behind it.
  describe "term_class:" do
    it "builds — and prices — the caller's Term subclass" do
      annotated = Class.new(MailerToGo::SPF::Term) do
        def meaning = "term #{position}: #{kind}"
      end

      a = MailerToGo::SPF::ChainAudit.call(
        hostname: "example.com",
        record: "v=spf1 include:p1.example.net ~all",
        resolver: resolver_for({ "p1.example.net" => ["v=spf1 ip4:203.0.113.1 ~all"] }),
        term_class: annotated
      )

      expect(a.terms.map(&:meaning)).to eq(["term 1: include", "term 2: all"])
      expect(a.terms.first.lookups).to eq(1)
    end
  end
end
