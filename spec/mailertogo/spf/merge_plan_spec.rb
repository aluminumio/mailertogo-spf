# frozen_string_literal: true

# The instruction "add a TXT record: v=spf1 include:… ~all" is correct only for
# a domain with no SPF. Handed to a domain that already has one, it produces two
# v=spf1 records — invalid per RFC 7208 §3.2, permerror per §4.5, and worse for
# the customer's mail than doing nothing at all. These examples pin the
# instruction we give instead.
#
# DNS is fully stubbed; nothing here touches the network.
RSpec.describe MailerToGo::SPF::MergePlan do
  def plan_for(zone, host: "example.com", **opts)
    MailerToGo::SPF.merge_plan(host, resolver: resolver_for(zone), **opts)
  end

  describe "no SPF record published yet" do
    it "keeps the standalone instruction" do
      plan = plan_for({})

      expect(plan.action).to eq(:publish)
      expect(plan.replacement?).to be(false)
      expect(plan.merged_record).to be_nil
      expect(plan.offered_record).to be_nil
      expect(plan.record).to eq(OUR_RECORD)
      expect(plan.resolved?).to be(true)
    end

    it "ignores unrelated TXT records at the same name" do
      plan = plan_for({ "example.com" => ["google-site-verification=abc123", "v=DMARC1"] })

      expect(plan.action).to eq(:publish)
    end
  end

  describe "an existing record the sender is not in" do
    it "merges the include into their Google record, before the terminal all" do
      plan = plan_for({ "example.com" => ["v=spf1 include:_spf.google.com ~all"],
                        "_spf.google.com" => ["v=spf1 ip4:35.190.247.0/24 ~all"], })

      expect(plan.action).to eq(:merge)
      expect(plan.replacement?).to be(true)
      expect(plan.duplicated?).to be(false)
      expect(plan.existing_records).to eq(["v=spf1 include:_spf.google.com ~all"])
      expect(plan.merged_record).to eq("v=spf1 include:_spf.google.com include:_spf.mailertogo.net ~all")
      expect(plan.offered_record).to eq(plan.merged_record)
    end

    # §5.1: -all tells receivers to REJECT mail the record does not authorize.
    # Rewriting it to ~all would quietly relax their policy for every sender
    # they have, not just for us.
    it "preserves a -all policy" do
      plan = plan_for({ "example.com" => ["v=spf1 include:secureserver.net -all"] })

      expect(plan.merged_record).to eq("v=spf1 include:secureserver.net include:_spf.mailertogo.net -all")
      expect(plan.all_qualifier).to eq("-")
    end

    it "preserves a ?all policy" do
      plan = plan_for({ "example.com" => ["v=spf1 include:spf.em.secureserver.net ?all"] })

      expect(plan.merged_record).to eq("v=spf1 include:spf.em.secureserver.net include:_spf.mailertogo.net ?all")
      expect(plan.all_qualifier).to eq("?")
    end

    # Records with no `all` at all exist. Appending one would newly instruct
    # receivers about mail that is unmatched today — a policy change nobody
    # asked for.
    it "does not invent an all when their record has none" do
      plan = plan_for({ "example.com" => ["v=spf1 include:_spf.google.com"] })

      expect(plan.merged_record).to eq("v=spf1 include:_spf.google.com include:_spf.mailertogo.net")
      expect(plan.all_qualifier).to be_nil
    end

    it "keeps their mechanisms in published order and adds ours last" do
      plan = plan_for({
        "example.com" => ["v=spf1 ip4:198.51.100.7 include:_spf.marketing.example include:sendgrid.net +a +mx ~all"],
      })

      expect(plan.merged_record).to eq(
        "v=spf1 ip4:198.51.100.7 include:_spf.marketing.example include:sendgrid.net +a +mx " \
        "include:_spf.mailertogo.net ~all"
      )
    end

    # A record that hardcodes the sender's IPs authenticates today and breaks
    # the day one moves (Authorization's :pinned). The merge is still the right
    # instruction.
    it "adds the include to a record that only pins the sender's IP addresses" do
      plan = plan_for({ "example.com" => ["v=spf1 ip4:192.0.2.10 ip4:192.0.2.11 ip4:192.0.2.128/25 -all"] })

      expect(plan.action).to eq(:merge)
      expect(plan.merged_record).to end_with("include:_spf.mailertogo.net -all")
    end

    # exp=/redirect= apply to the whole record wherever they sit (§4.6.1), so
    # they survive; a mechanism stranded after `all` never was evaluated.
    it "keeps modifiers and drops mechanisms stranded after all" do
      plan = plan_for({
        "example.com" => ["v=spf1 include:_spf.google.com ~all include:stranded.example exp=why.example.com"],
      })

      expect(plan.merged_record).to eq(
        "v=spf1 include:_spf.google.com include:_spf.mailertogo.net ~all exp=why.example.com"
      )
      expect(plan.notes.join).to include("stranded.example")
    end

    # Records ending `~all;google-site-verification=…` are published in the
    # wild: the `;`-joined fragment is not a valid SPF term at all.
    it "strips junk glued onto their all and says so" do
      plan = plan_for({ "example.com" => ["v=spf1 include:_spf.google.com ~all;google-site-verification=xyz"] })

      expect(plan.merged_record).to eq("v=spf1 include:_spf.google.com include:_spf.mailertogo.net ~all")
      expect(plan.notes.join).to include("google-site-verification")
    end
  end

  describe "already in the broken two-record state" do
    it "reports the duplicate and offers one merged replacement" do
      plan = plan_for({
        "example.com" => ["v=spf1 include:_spf.google.com ~all", OUR_RECORD],
        "_spf.google.com" => ["v=spf1 ip4:35.190.247.0/24 ~all"],
      })

      expect(plan.action).to eq(:deduplicate)
      expect(plan.duplicated?).to be(true)
      expect(plan.replacement?).to be(true)
      expect(plan.existing_records.size).to eq(2)
      expect(plan.merged_record).to eq("v=spf1 include:_spf.google.com include:_spf.mailertogo.net ~all")
      expect(plan.offered_record).to eq(plan.merged_record)
    end

    # THEIR record is the policy record — its qualifier wins over the one in the
    # record we told them to publish.
    it "takes the all qualifier from their record, not from ours" do
      plan = plan_for({ "example.com" => [OUR_RECORD, "v=spf1 include:secureserver.net -all"] })

      expect(plan.action).to eq(:deduplicate)
      expect(plan.merged_record).to eq("v=spf1 include:secureserver.net include:_spf.mailertogo.net -all")
    end

    # Their record has no `all`, ours does. Falling back to the one that exists
    # keeps the merged line saying what a record at that name already says.
    it "falls back to our all when their record has none" do
      plan = plan_for({ "example.com" => ["v=spf1 include:_spf.google.com", OUR_RECORD] })

      expect(plan.merged_record).to eq("v=spf1 include:_spf.google.com include:_spf.mailertogo.net ~all")
    end

    # Two records of their own, neither naming the sender, with an overlapping
    # include between them.
    it "deduplicates repeated mechanisms across both records" do
      plan = plan_for({
        "example.com" => [
          "v=spf1 include:spf.protection.outlook.com -all",
          "v=spf1 +a +mx +ip4:198.51.100.87 include:spf.web-hosting.com include:spf.protection.outlook.com ~all",
        ],
      })

      expect(plan.action).to eq(:deduplicate)
      expect(plan.merged_record.scan("include:spf.protection.outlook.com").size).to eq(1)
      expect(plan.merged_record).to eq(
        "v=spf1 include:spf.protection.outlook.com +a +mx +ip4:198.51.100.87 " \
        "include:spf.web-hosting.com include:_spf.mailertogo.net -all"
      )
    end

    # A variant spelling of the sender's own zone that is NOT registered as one
    # of its names is somebody else's mechanism as far as we know, so it is
    # carried across rather than silently dropped.
    it "keeps an unregistered spelling of our own zone as a mechanism" do
      plan = plan_for({ "example.com" => [OUR_RECORD, "v=spf1 include:_spf.eu.mailertogo.net ~all"] })

      expect(plan.action).to eq(:deduplicate)
      expect(plan.merged_record).to eq(
        "v=spf1 include:_spf.eu.mailertogo.net include:_spf.mailertogo.net ~all"
      )
    end

    it "drops a spelling that IS registered as one of our names" do
      plan = plan_for({ "example.com" => [OUR_RECORD, "v=spf1 include:_spf.eu.mailertogo.net ~all"] },
                      aliases: ["mailertogo.net", "_spf.eu.mailertogo.net"])

      expect(plan.merged_record).to eq("v=spf1 include:_spf.mailertogo.net ~all")
    end
  end

  describe "a record that already reaches the sender" do
    it "leaves a direct include alone" do
      plan = plan_for({ "example.com" => ["v=spf1 include:_spf.google.com include:_spf.mailertogo.net ~all"] })

      expect(plan.action).to eq(:satisfied)
      expect(plan.replacement?).to be(false)
      expect(plan.offered_record).to be_nil
    end

    # A record naming the outer alias already passes at every receiver.
    # Rewriting it to the leaf would be churn for no gain.
    it "leaves a record that reaches the sender through an outer alias alone" do
      plan = plan_for({ "example.com" => ["v=spf1 include:spf.hosting.example include:mailertogo.net ~all"],
                        "spf.hosting.example" => ["v=spf1 ip4:198.51.100.0/18 ~all"], })

      expect(plan.action).to eq(:satisfied)
    end
  end

  # RFC 7208 §4.6.4 caps an evaluation at 10 DNS-querying mechanisms. Merging
  # can push a record over it, and a record over it permerrors for everyone — so
  # say that, rather than handing over a line that breaks on arrival.
  describe "when the merge would exceed the 10-lookup cap" do
    # 10 include: terms, each resolving to a flat ip4 record — exactly at the
    # cap before the sender is added.
    let(:at_the_cap) do
      zone = { "example.com" => ["v=spf1 #{(1..10).map { |i| "include:p#{i}.example" }.join(" ")} ~all"] }
      (1..10).each { |i| zone["p#{i}.example"] = ["v=spf1 ip4:203.0.113.#{i} ~all"] }
      zone
    end

    it "flags the overage and withholds the merged line" do
      plan = plan_for(at_the_cap)

      expect(plan.action).to eq(:merge)
      expect(plan.over_limit?).to be(true)
      expect(plan.lookups).to eq(11)
      expect(plan.lookup_limit).to eq(10)
      # The merged record is still computed — a UI may show it for reference —
      # but it is NOT what we offer them to publish.
      expect(plan.merged_record).to include("include:_spf.mailertogo.net")
      expect(plan.offered_record).to be_nil
      expect(plan.warning?).to be(true)
    end

    it "offers the merged line when the result lands exactly on the cap" do
      zone = { "example.com" => ["v=spf1 #{(1..9).map { |i| "include:p#{i}.example" }.join(" ")} ~all"] }
      (1..9).each { |i| zone["p#{i}.example"] = ["v=spf1 ip4:203.0.113.#{i} ~all"] }

      plan = plan_for(zone)

      expect(plan.over_limit?).to be(false)
      expect(plan.lookups).to eq(10)
      expect(plan.offered_record).to eq(plan.merged_record)
    end
  end

  describe "when DNS does not answer" do
    it "falls back to the standalone instruction rather than guessing" do
      plan = plan_for({ "example.com" => nil })

      expect(plan.action).to eq(:publish)
      expect(plan.resolved?).to be(false)
      expect(plan.merged_record).to be_nil
      expect(plan.record).to eq(OUR_RECORD)
    end

    it "does not claim a lookup overage it could not measure" do
      # The apex answers; one of their includes does not.
      plan = plan_for({ "example.com" => ["v=spf1 include:broken.example ~all"], "broken.example" => nil })

      expect(plan.action).to eq(:merge)
      expect(plan.over_limit?).to be(false)
      expect(plan.lookups).to be_nil
      expect(plan.offered_record).to eq("v=spf1 include:broken.example include:_spf.mailertogo.net ~all")
    end

    it "says nothing when the record to merge in has no include mechanism" do
      plan = plan_for({ "example.com" => ["v=spf1 include:_spf.google.com ~all"] },
                      record: "not an spf record")

      expect(plan.action).to eq(:publish)
      expect(plan.resolved?).to be(false)
    end
  end

  # Callers ask the plan these questions directly rather than re-deriving them
  # from a flattened hash: this picks one of four instructions for somebody
  # about to edit live DNS, so a typo must raise at the call site instead of
  # silently rendering the wrong branch.
  describe "the questions a DNS-records table asks" do
    let(:spf_row) { { name: "example.com", value: OUR_RECORD } }
    let(:dkim_row) { { name: "tap._domainkey.example.com", value: "v=DKIM1; p=abc" } }

    describe "#severity / #warning?" do
      it "is a plain notice for a first-time merge — nothing is wrong yet" do
        plan = plan_for({ "example.com" => ["v=spf1 include:_spf.google.com ~all"] })

        expect(plan.warning?).to be(false)
        expect(plan.severity).to eq(:info)
      end

      it "warns once they are already publishing two records" do
        plan = plan_for({ "example.com" => ["v=spf1 include:_spf.google.com ~all", OUR_RECORD] })

        expect(plan.warning?).to be(true)
        expect(plan.severity).to eq(:warning)
      end

      it "warns when the merge would not fit in the lookup budget" do
        zone = { "example.com" => ["v=spf1 #{(1..10).map { |i| "include:p#{i}.example" }.join(" ")} ~all"] }
        (1..10).each { |i| zone["p#{i}.example"] = ["v=spf1 ip4:203.0.113.#{i} ~all"] }

        plan = plan_for(zone)

        expect(plan.over_limit?).to be(true)
        expect(plan.severity).to eq(:warning)
      end

      it "has nothing to say when there is no instruction to give" do
        expect(plan_for({}).severity).to eq(:info)
        expect(MailerToGo::SPF::Plan.none.severity).to eq(:info)
      end
    end

    describe "#replaces? / #value_for" do
      it "swaps the merged line into the SPF row and leaves every other row alone" do
        plan = plan_for({ "example.com" => ["v=spf1 include:_spf.google.com ~all"] })

        expect(plan.replaces?(**spf_row)).to be(true)
        expect(plan.value_for(**spf_row)).to eq("v=spf1 include:_spf.google.com include:_spf.mailertogo.net ~all")
        expect(plan.replaces?(**dkim_row)).to be(false)
        expect(plan.value_for(**dkim_row)).to eq("v=DKIM1; p=abc")
      end

      it "matches the SPF row regardless of how the row spells the name" do
        plan = plan_for({ "example.com" => ["v=spf1 include:_spf.google.com ~all"] })

        expect(plan.replaces?(name: "Example.COM.", value: OUR_RECORD)).to be(true)
      end

      # Withholding lives in offered_record, so the row inherits it — there is
      # no second place that could decide to render the over-cap line anyway.
      it "leaves the row alone when the merged line is withheld for the lookup cap" do
        zone = { "example.com" => ["v=spf1 #{(1..10).map { |i| "include:p#{i}.example" }.join(" ")} ~all"] }
        (1..10).each { |i| zone["p#{i}.example"] = ["v=spf1 ip4:203.0.113.#{i} ~all"] }

        plan = plan_for(zone)

        expect(plan.replaces?(**spf_row)).to be(false)
        expect(plan.value_for(**spf_row)).to eq(OUR_RECORD)
      end

      it "leaves the row alone when nothing is published to merge with" do
        plan = plan_for({})

        expect(plan.replaces?(**spf_row)).to be(false)
        expect(plan.value_for(**spf_row)).to eq(OUR_RECORD)
      end
    end

    # A table may render with no plan at all. A null plan means no caller has to
    # nil-check before asking a question.
    describe ".none" do
      it "answers every question as 'no instruction'" do
        none = MailerToGo::SPF::Plan.none

        expect(none.replacement?).to be(false)
        expect(none.duplicated?).to be(false)
        expect(none.over_limit?).to be(false)
        expect(none.warning?).to be(false)
        expect(none.resolved?).to be(false)
        expect(none.offered_record).to be_nil
        expect(none.existing_records).to eq([])
        expect(none.notes).to eq([])
        expect(none.replaces?(**spf_row)).to be(false)
        expect(none.value_for(**spf_row)).to eq(OUR_RECORD)
      end
    end
  end

  it "merges for a sender that is not MailerToGo" do
    plan = plan_for({ "example.com" => ["v=spf1 include:_spf.google.com ~all"] },
                    include: "spf.example.net")

    expect(plan.merged_record).to eq("v=spf1 include:_spf.google.com include:spf.example.net ~all")
    expect(plan.record).to eq("v=spf1 include:spf.example.net ~all")
  end

  it "handles TXT records split across quoted character-strings" do
    plan = plan_for({ "example.com" => ["\"v=spf1 include:_spf.google.com \" \"~all\""] })

    expect(plan.action).to eq(:merge)
    expect(plan.merged_record).to eq("v=spf1 include:_spf.google.com include:_spf.mailertogo.net ~all")
  end
end
