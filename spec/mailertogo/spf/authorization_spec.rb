# frozen_string_literal: true

RSpec.describe MailerToGo::SPF::Authorization do
  # The sender under test is the default one: include _spf.mailertogo.net, with
  # mailertogo.net as an equally-valid outer alias.
  def authorize(zone, host: "example.com", **opts)
    MailerToGo::SPF.authorize(host, resolver: resolver_for(zone), **opts)
  end

  describe "a record that reaches the sender through an outer alias" do
    # The case a literal string match gets wrong. This record passes SPF at
    # every real receiver — `include:mailertogo.net` resolves to a record that
    # includes the leaf — so anything that looks only for the leaf token reports
    # a false failure against a perfectly healthy domain.
    it "passes a record that includes the outer alias, not the literal leaf" do
      r = authorize({
        "example.com" => ["v=spf1 include:spf.hosting.example include:mailertogo.net ~all"],
        "spf.hosting.example" => ["v=spf1 ip4:198.51.100.0/18 ~all"],
      })

      expect(r.status).to eq(:pass)
      expect(r.matched).to eq("mailertogo.net")
      expect(r.detail).to match(/mailertogo\.net/)
    end

    it "passes when the leaf is reachable only after two hops" do
      r = authorize({
        "example.com" => ["v=spf1 include:mail.partner.example ~all"],
        "mail.partner.example" => ["v=spf1 include:mailertogo.net ~all"],
      })

      expect(r.status).to eq(:pass)
      expect(r.matched).to eq("mailertogo.net")
      expect(r.detail).to match(/include chain/)
    end
  end

  it "still passes a direct include of the canonical leaf" do
    r = authorize({ "example.com" => ["v=spf1 include:_spf.mailertogo.net include:sendgrid.net ~all"] })

    expect(r.status).to eq(:pass)
    expect(r.matched).to eq("_spf.mailertogo.net")
  end

  it "authorizes a different sender when asked about one" do
    r = authorize({ "example.com" => ["v=spf1 include:spf.example.net ~all"] },
                  include: "spf.example.net")

    expect(r.status).to eq(:pass)
    expect(r.matched).to eq("spf.example.net")
  end

  it "does not treat our aliases as a foreign sender's" do
    r = authorize({ "example.com" => ["v=spf1 include:mailertogo.net ~all"] },
                  include: "spf.example.net")

    expect(r.status).to eq(:fail)
  end

  # Pinning is NOT an include. Sending addresses move — relay nodes rotate,
  # ranges are activated and retired — so a record hardcoding them authenticates
  # today and breaks silently tomorrow. It gets its own status, never :pass.
  describe "a record pinned to the sender's IP addresses" do
    it "reports :pinned — not :pass — when it lists every current range" do
      r = authorize({ "example.com" => ["v=spf1 ip4:192.0.2.10 ip4:192.0.2.11 ip4:192.0.2.128/25 -all"] })

      expect(r.status).to eq(:pinned)
      expect(r.reason).to eq(:pinned_full)
      expect(r.pass?).to be(false)
      expect(r.matched).to be_nil
      expect(r.defect).to eq(:ip_pinned)
      expect(r.detail).to match(/stops silently/)
    end

    it "reports :pinned_partial when it covers only some of the ranges" do
      r = authorize({ "example.com" => ["v=spf1 ip4:192.0.2.10 -all"] })

      expect(r.status).to eq(:pinned)
      expect(r.reason).to eq(:pinned_partial)
      expect(r.detail).to match(/only 1 of the 3 current ranges/)
    end

    it "reports :pinned_partial when it names one address inside a sending CIDR" do
      r = authorize({ "example.com" => ["v=spf1 ip4:192.0.2.130 -all"] })

      expect(r.status).to eq(:pinned)
      expect(r.reason).to eq(:pinned_partial)
    end

    it "prefers the include when a record both includes the sender and lists IPs" do
      r = authorize({ "example.com" => ["v=spf1 ip4:192.0.2.10 include:_spf.mailertogo.net -all"] })

      expect(r.status).to eq(:pass)
    end

    it "is not pinned when the IPs listed belong to somebody else" do
      r = authorize({ "example.com" => ["v=spf1 ip4:203.0.113.0/24 -all"] })

      expect(r.status).to eq(:fail)
    end
  end

  describe "records that genuinely do not authorize the sender" do
    it "fails a record with no relationship to the sender, after resolving the chain" do
      r = authorize({
        "example.com" => ["v=spf1 include:sendgrid.net include:_spf.google.com ~all"],
        "sendgrid.net" => ["v=spf1 ip4:198.51.100.0/24 ~all"],
        "_spf.google.com" => ["v=spf1 include:_netblocks.google.com ~all"],
        "_netblocks.google.com" => ["v=spf1 ip4:35.190.247.0/24 ~all"],
      })

      expect(r.status).to eq(:fail)
      expect(r.detail).to match(/does not authorize/)
    end

    it "does not match a lookalike domain" do
      r = authorize({
        "example.com" => ["v=spf1 include:notmailertogo.net ~all"],
        "notmailertogo.net" => ["v=spf1 ip4:203.0.113.9 ~all"],
      })

      expect(r.status).to eq(:fail)
    end

    it "fails when the domain publishes no SPF at all" do
      expect(authorize({}).status).to eq(:fail)
      expect(authorize({}).detail).to match(/No v=spf1 record/)
    end

    it "fails when the apex TXT is not an SPF record" do
      r = authorize({ "example.com" => ["google-site-verification=abc123"] })

      expect(r.status).to eq(:fail)
    end
  end

  describe "RFC 7208 §4.6.4 — the 10-lookup cap" do
    # `count` include mechanisms, each resolving to a terminal record. Past 10 a
    # receiver PERMERRORs and the record never passes, sender present or not.
    def chain_of(count, tail: "~all")
      includes = (1..count).map { |i| "include:hop#{i}.example" }
      zone = { "example.com" => ["v=spf1 #{includes.join(" ")} #{tail}"] }
      (1..count).each { |i| zone["hop#{i}.example"] = ["v=spf1 ip4:10.0.#{i}.0/24 ~all"] }
      zone
    end

    it "passes a record sitting exactly at the limit" do
      zone = chain_of(9)
      zone["example.com"] = [zone["example.com"].first.sub("~all", "include:mailertogo.net ~all")]

      r = authorize(zone)
      expect(r.lookups).to eq(10)
      expect(r.status).to eq(:pass)
    end

    # §4.6.4 caps the terms an evaluation may EVALUATE, and §4.6.2 stops
    # evaluation at the first matching mechanism — so terms sitting after the
    # match are never looked up and never spend budget.
    it "stops counting at the matching mechanism, ignoring terms after it" do
      zone = chain_of(9)
      # 9 hops, then the sender (lookup 10 — the match), then 5 more includes
      # that a receiver never evaluates because the record already matched.
      extra = (1..5).map { |i| "include:tail#{i}.example" }.join(" ")
      zone["example.com"] = [zone["example.com"].first.sub("~all", "include:mailertogo.net #{extra} ~all")]
      (1..5).each { |i| zone["tail#{i}.example"] = ["v=spf1 ip4:10.9.#{i}.0/24 ~all"] }

      r = authorize(zone)
      expect(r.status).to eq(:pass)
      expect(r.lookups).to eq(10)
    end

    it "permerrors a chain whose match lands one term past the limit" do
      zone = chain_of(10)
      zone["example.com"] = [zone["example.com"].first.sub("~all", "include:mailertogo.net ~all")]

      r = authorize(zone)
      expect(r.status).to eq(:permerror)
      expect(r.reason).to eq(:lookup_limit)
      expect(r.permerror_with_sender_published?).to be(true)
    end

    it "permerrors a chain that blows the budget with no match at all" do
      r = authorize(chain_of(12))

      expect(r.status).to eq(:permerror)
      expect(r.reason).to eq(:lookup_limit)
      expect(r.permerror_with_sender_published?).to be(false)
    end

    # The shape that makes whole-tree counting wrong, taken from a real record.
    # The match lands on DNS-querying term 10 — inside budget — so this record
    # PASSES, even though the apex has a sixth include after it that would tip a
    # naive count of the whole tree over the cap. A conformant receiver stops at
    # the match and so do we.
    it "passes a record whose match lands on term 10 with zero headroom" do
      r = authorize({
        "example.com" => ["v=spf1 include:mgr-0a1b2c3d4e.spf.example.com include:_spf.google.com " \
                          "include:mailgun.org include:spf.partner.example include:_spf.mailertogo.net ~all"],
        "mgr-0a1b2c3d4e.spf.example.com" => ["v=spf1 include:_spf.google.com ~all"],
        "_spf.google.com" => ["v=spf1 ip4:74.125.0.0/16 ip4:209.85.128.0/17 ip6:2001:4860:4864::/56 " \
                              "ip6:2404:6800:4864::/56 ip6:2607:f8b0:4864::/56 ip6:2800:3f0:4864::/56 " \
                              "ip6:2a00:1450:4864::/56 ip6:2c0f:fb50:4864::/56 ~all"],
        "mailgun.org" => ["v=spf1 include:_spf.mailgun.org include:_spf.eu.mailgun.org -all"],
        "_spf.mailgun.org" => ["v=spf1 include:_spf1.mailgun.org include:_spf2.mailgun.org ~all"],
        "_spf1.mailgun.org" => ["v=spf1 ip4:209.61.151.0/24 ip4:166.78.68.0/22 ~all"],
        "_spf2.mailgun.org" => ["v=spf1 ip4:104.130.122.0/23 ip4:146.20.112.0/26 ~all"],
        "_spf.eu.mailgun.org" => ["v=spf1 ip4:141.193.32.0/23 ip4:159.135.140.80/29 ~all"],
        "spf.partner.example" => ["v=spf1 include:_spf.mailertogo.net ~all"],
      })

      expect(r.status).to eq(:pass)
      expect(r.lookups).to eq(10)
      expect(r.defect).to be_nil
    end

    it "reports a record that exceeds the limit as a permerror failure" do
      r = authorize(chain_of(11))

      expect(r.status).to eq(:permerror)
      expect(r.failed?).to be(true)
      expect(r.detail).to match(/more than 10 DNS lookups/)
    end

    it "permerrors even when the sender's include is present but the record is over budget" do
      zone = chain_of(11)
      zone["example.com"] = [zone["example.com"].first.sub("~all", "include:mailertogo.net ~all")]

      r = authorize(zone)
      expect(r.status).to eq(:permerror)
    end

    it "counts a/mx/exists mechanisms against the budget, as receivers do" do
      r = authorize({ "example.com" => ["v=spf1 a mx exists:%{i}.spf.example include:mailertogo.net ~all"] })

      expect(r.lookups).to eq(4)
      expect(r.status).to eq(:pass)
    end

    it "does not loop forever on a self-referential include" do
      r = authorize({
        "example.com" => ["v=spf1 include:loop.example ~all"],
        "loop.example" => ["v=spf1 include:example.com include:loop.example ~all"],
      })

      expect(r.status).to eq(:fail)
      expect(r.lookups).to be <= described_class::MAX_DNS_LOOKUPS + 1
    end

    it "permerrors when a name publishes more than one v=spf1 record (§4.5)" do
      r = authorize({ "example.com" => ["v=spf1 include:mailertogo.net ~all", "v=spf1 ip4:203.0.113.9 ~all"] })

      expect(r.status).to eq(:permerror)
      expect(r.detail).to match(/more than one v=spf1/)
      # Broken for receivers, but the sender's record IS published — the
      # distinction a gating caller needs so it does not un-verify the domain.
      expect(r.permerror_with_sender_published?).to be(true)
    end

    it "reports a permerror with no mention of the sender as an outright failure" do
      r = authorize({ "example.com" => ["v=spf1 include:_spf.google.com ~all", "v=spf1 ip4:203.0.113.9 ~all"] })

      expect(r.status).to eq(:permerror)
      expect(r.permerror_with_sender_published?).to be(false)
    end

    it "still sees the sender's include in a record that blew the lookup budget" do
      zone = chain_of(11)
      zone["example.com"] = [zone["example.com"].first.sub("~all", "include:mailertogo.net ~all")]

      r = authorize(zone)
      expect(r.status).to eq(:permerror)
      expect(r.permerror_with_sender_published?).to be(true)
    end

    it "permerrors the whole evaluation when an INCLUDED name has duplicate records" do
      r = authorize({
        "example.com" => ["v=spf1 include:broken.example ~all"],
        "broken.example" => ["v=spf1 ip4:203.0.113.1 ~all", "v=spf1 ip4:203.0.113.2 ~all"],
      })

      expect(r.status).to eq(:permerror)
      expect(r.detail).to match(/broken\.example/)
    end
  end

  describe "DNS failure modes (must degrade, never raise or false-fail)" do
    it "returns :unknown when the apex lookup fails" do
      r = MailerToGo::SPF.authorize("example.com", resolver: ->(_n) {})

      expect(r.status).to eq(:unknown)
      expect(r.unknown?).to be(true)
      expect(r.failed?).to be(false)
    end

    it "returns :unknown when an include in the chain fails to resolve" do
      resolver = lambda do |name|
        case name
        when "example.com" then ["v=spf1 include:flaky.example ~all"]
        when "flaky.example" then nil # timeout
        else []
        end
      end
      r = MailerToGo::SPF.authorize("example.com", resolver: resolver)

      expect(r.status).to eq(:unknown)
    end

    it "marks a result partial when part of the chain did not resolve" do
      r = authorize({
        "example.com" => ["v=spf1 include:flaky.example include:mailertogo.net ~all"],
        "flaky.example" => nil,
      })

      expect(r.status).to eq(:pass)
      expect(r.partial?).to be(true)
    end

    it "treats NXDOMAIN / no-TXT inside a chain as an unmatched branch, not an error" do
      r = authorize({
        "example.com" => ["v=spf1 include:gone.example include:mailertogo.net ~all"],
        # gone.example simply has no TXT
      })

      expect(r.status).to eq(:pass)
      expect(r.partial?).to be(false)
    end

    it "does not raise on malformed terms, empty includes, or junk TXT" do
      r = authorize({ "example.com" => ["v=spf1 include: ip4:not-an-ip ip6:::/0 redirect= ~all"] })

      expect { r }.not_to raise_error
      expect(r.status).to eq(:fail)
    end

    it "handles a TXT record split across quoted character-strings" do
      r = authorize({ "example.com" => ['"v=spf1 include:_spf.mailer" "togo.net ~all"'] })

      expect(r.status).to eq(:pass)
    end

    it "is case- and trailing-dot-insensitive" do
      r = authorize({ "example.com" => ["V=SPF1 INCLUDE:MailerToGo.NET. ~all"] })

      expect(r.status).to eq(:pass)
    end
  end

  describe "the redirect= modifier" do
    it "follows redirect= to reach the sender" do
      r = authorize({
        "example.com" => ["v=spf1 redirect=spf.partner.example"],
        "spf.partner.example" => ["v=spf1 include:mailertogo.net ~all"],
      })

      expect(r.status).to eq(:pass)
    end

    # §6.1: redirect= is a modifier, evaluated only after every mechanism has
    # failed to match — and ignored entirely when the record has an `all`.
    it "ignores redirect= when the record also has an all mechanism" do
      r = authorize({
        "example.com" => ["v=spf1 ip4:203.0.113.1 -all redirect=spf.partner.example"],
        "spf.partner.example" => ["v=spf1 include:mailertogo.net ~all"],
      })

      expect(r.status).to eq(:fail)
      expect(r.lookups).to eq(0)
    end

    it "spends no budget on mechanisms sitting after all" do
      r = authorize({ "example.com" => ["v=spf1 -all include:hop.example include:mailertogo.net"] })

      expect(r.status).to eq(:fail)
      expect(r.lookups).to eq(0)
    end
  end

  # A conformant evaluator distinguishes SoftFail from Fail. The distinction is
  # real (receivers mark vs. reject), so we carry the qualifier as a field on
  # the result — the status stays four-valued because no caller's decision
  # changes, only what it can tell the domain owner.
  describe "the all qualifier (§5.1)" do
    it "reports ~all as a softfail and says receivers only mark the mail" do
      r = authorize({ "example.com" => ["v=spf1 include:_spf.google.com ~all"] })

      expect(r.status).to eq(:fail)
      expect(r.all_qualifier).to eq(:softfail)
      expect(r.softfail?).to be(true)
      expect(r.detail).to match(/mark that mail rather than rejecting/)
    end

    it "reports -all as a hard fail and says receivers reject the mail" do
      r = authorize({ "example.com" => ["v=spf1 include:_spf.google.com -all"] })

      expect(r.status).to eq(:fail)
      expect(r.all_qualifier).to eq(:fail)
      expect(r.softfail?).to be(false)
      expect(r.detail).to match(/reject that mail outright/)
    end

    it "treats a bare all as +all and ?all as neutral" do
      expect(authorize({ "example.com" => ["v=spf1 all"] }).all_qualifier).to eq(:pass)
      expect(authorize({ "example.com" => ["v=spf1 ?all"] }).all_qualifier).to eq(:neutral)
    end

    it "takes the qualifier from a redirect target when the apex has no all" do
      r = authorize({
        "example.com" => ["v=spf1 redirect=spf.partner.example"],
        "spf.partner.example" => ["v=spf1 ip4:203.0.113.0/24 -all"],
      })

      expect(r.status).to eq(:fail)
      expect(r.all_qualifier).to eq(:fail)
    end

    # An included record's `all` never escapes the include (§5.2) — only the
    # outer record decides what happens to unauthorized mail.
    it "ignores the all of an included record" do
      r = authorize({
        "example.com" => ["v=spf1 include:partner.example ~all"],
        "partner.example" => ["v=spf1 ip4:203.0.113.0/24 -all"],
      })

      expect(r.all_qualifier).to eq(:softfail)
    end

    it "is nil for a record with no all at all" do
      expect(authorize({ "example.com" => ["v=spf1 ip4:203.0.113.1"] }).all_qualifier).to be_nil
    end
  end

  describe "evaluating a record that is not published yet" do
    it "prices a supplied record instead of the one DNS holds" do
      r = authorize({ "example.com" => ["v=spf1 include:_spf.google.com ~all"] },
                    published: "v=spf1 include:_spf.google.com include:_spf.mailertogo.net ~all")

      expect(r.status).to eq(:pass)
      expect(r.lookups).to eq(2)
    end

    it "resolves the supplied record's includes against real DNS" do
      r = authorize({
        "example.com" => [], # nothing published at the apex yet
        "partner.example" => ["v=spf1 include:mailertogo.net ~all"],
      }, published: "v=spf1 include:partner.example ~all")

      expect(r.status).to eq(:pass)
      expect(r.lookups).to eq(2)
    end
  end
end
