# frozen_string_literal: true

require "mailertogo/spf/record"
require "mailertogo/spf/plan"
require "mailertogo/spf/authorization"

module MailerToGo
  module SPF
    # What a domain owner should PUBLISH for SPF, given what is ALREADY at that
    # name in DNS.
    #
    # Why this exists: the standard setup instruction — "add a TXT record:
    # v=spf1 include:_spf.mailertogo.net ~all" — is correct only for a domain
    # with no SPF at all. A domain that already has SPF (Google Workspace, a
    # registrar's default, Microsoft 365, another ESP) and follows that
    # instruction literally ends up publishing a SECOND v=spf1 record beside the
    # first. RFC 7208 §3.2 says a domain MUST NOT have more than one, and §4.5
    # makes the pair a permerror — which does not merely fail to authorize the
    # new sender, it breaks SPF for every sender the domain had. The customer's
    # mail gets worse, and they did exactly what they were told.
    #
    # The only correct action for a domain that already has SPF is to MERGE the
    # new mechanism into the existing record. So: before rendering the
    # instruction, look at the name. If SPF is already there, hand them ONE
    # merged record to REPLACE it with.
    #
    # Three things this is careful about, because each is a way to make a
    # customer's mail worse rather than better:
    #
    #   * Their `all` qualifier is THEIR policy (§5.1) — `-all` rejects
    #     unauthorized mail, `~all` only marks it. Carry it across verbatim
    #     rather than quietly relaxing (or tightening) what receivers do with
    #     mail nobody asked us about.
    #   * The new include goes LAST, immediately before the terminal `all`,
    #     because a mechanism after `all` is never evaluated (§5.1/§6.1).
    #   * Merging costs DNS lookups, and §4.6.4 caps an evaluation at 10. A
    #     record already near the cap can be pushed over it by one more include,
    #     and a record over the cap permerrors for everyone. Measure the merged
    #     record and say so, rather than handing over a line that breaks on
    #     arrival.
    #
    # Reads DNS, changes nothing. When DNS does not answer we fall back to the
    # standalone instruction rather than guessing — better to under-help than to
    # tell someone to replace a record we could not read.
    class MergePlan
      # What a term IS — is it the terminal `all` (with whatever junk is glued
      # onto it), is it a modifier, does it name the sender — is asked of Term
      # rather than re-matched here. There was a second, informal copy of that
      # knowledge in this file; two readings of the same term is exactly how a
      # record ending `~all;google-site-verification=…` ends up merged one way
      # and described another.
      #
      # name          — the DNS name the record goes at.
      # record        — the standalone record you would otherwise have told them
      #                 to publish, e.g. Sender#record. It is what a :publish
      #                 plan hands back; the merged line is built from `sender`.
      # sender        — a Sender: the names that mean "me".
      # resolver      — anything responding to #call(name); see Resolver.
      # authorization — an already-resolved Result for this same name, when the
      #                 caller has one. Saves walking the chain twice; nil means
      #                 we resolve it ourselves.
      # logger        — optional, anything responding to #warn.
      def self.call(name, record:, sender:, resolver:, authorization: nil, logger: nil)
        new(name, record: record, sender: sender, resolver: resolver,
                  authorization: authorization, logger: logger).run
      end

      def initialize(name, record:, sender:, resolver:, authorization: nil, logger: nil)
        @name = Record.normalize_name(name)
        @record = record.to_s
        @sender = sender
        @include_name = sender.include_name
        @lookup = resolver
        @authorization = authorization
        @logger = logger
        @notes = []
        @all_qualifier = nil
      end

      def run
        txts = @lookup.call(@name)
        return plan(:publish, resolved: false) if txts.nil? # DNS did not answer

        records = Array(txts).map { |t| Record.normalize_txt(t) }.select { |t| Record.spf_record?(t) }
        return plan(:publish) if records.empty?

        # A single record that already reaches the sender — directly or through
        # an outer alias — is healthy. Never rewrite a working record.
        return plan(:satisfied, existing_records: records) if records.one? && authorized?

        merged = merge(records)

        # Nothing of ours to add (a single record that already names the sender
        # but has an unrelated defect of its own — that is a different warning,
        # not a merge instruction).
        return plan(:satisfied, existing_records: records) if records.one? && same_terms?(merged, records.first)

        budget = measure(merged)
        plan(records.size > 1 ? :deduplicate : :merge,
             existing_records: records,
             merged_record: merged,
             all_qualifier: @all_qualifier,
             lookups: budget[:lookups],
             over_lookup_limit: budget[:over_limit])
      end

      private

      # Does the currently-published record already authorize the sender? Uses
      # the caller's result when it has one, so a diagnostics page does not walk
      # the same chain twice.
      def authorized?
        result = @authorization ||
                 Authorization.call(@name, sender: @sender, resolver: @lookup, logger: @logger)
        result.pass?
      rescue StandardError => e
        warn_failure("authorization check", e)
        false
      end

      # Their mechanisms plus ours, in ONE record.
      #
      # Record order is deliberate: records that are NOT ours come first,
      # because theirs is the policy record and its `all` is the one to
      # preserve. Within a record, terms keep their published order — an SPF
      # record's mechanisms are evaluated in order, and a customer may well have
      # put a cheap ip4 first on purpose.
      def merge(records)
        theirs, ours = records.partition { |r| !ours?(r) }
        mechanisms = []
        modifiers = []
        @all_qualifier = nil

        (theirs + ours).each do |record|
          seen_all = false

          Record.parse_terms(record).each do |term|
            if term.all?
              seen_all = true
              # First `all` across the ordered records wins — theirs, not ours.
              # A bare `all` is `+all` (§4.6.2); spell it out so the merged line
              # says plainly what it does.
              @all_qualifier ||= term.qualifier || "+"
              if (junk = term.all_suffix)
                @notes << "Dropped #{junk.inspect}, which was glued onto your #{term.qualifier}all " \
                          "and isn't a valid SPF term — publish it as its own TXT record if you still need it."
              end
              next
            end

            if term.modifier
              # redirect=/exp= are modifiers, not mechanisms: they apply to the
              # whole record wherever they sit, so keep them (deduped by
              # modifier name).
              modifiers << term unless modifiers.any? { |t| t.modifier == term.modifier }
              next
            end

            if seen_all
              # Unreachable in the published record (nothing after `all` is ever
              # evaluated). Dropping it preserves the record's exact behavior;
              # keeping it would newly authorize a sender receivers ignore today.
              @notes << "Dropped #{term.raw.inspect}, which sat after your #{@all_qualifier}all " \
                        "and was never evaluated."
              next
            end

            next if sender_term?(term)

            mechanisms << term.raw unless mechanisms.any? { |t| t.casecmp?(term.raw) }
          end
        end

        # Ours goes last — right before the terminal `all`, which matches
        # everything and ends evaluation.
        terms = mechanisms + ["include:#{@include_name}"]
        terms << "#{@all_qualifier}all" if @all_qualifier
        terms += modifiers.map(&:raw)
        "v=spf1 #{terms.join(" ")}"
      end

      # The merged line's real cost to a receiver: evaluate it exactly as a
      # published record would be evaluated, and let §4.6.4 apply. Our include
      # sits last, so the budget reported is the budget the sender's own mail
      # spends.
      def measure(merged)
        result = Authorization.call(@name, sender: @sender, resolver: @lookup,
                                           published: merged, logger: @logger)
        if result.unknown? || result.partial?
          # A resolver hiccup mid-chain: the count is a floor, not the cost.
          # Report nothing rather than a budget we could not finish measuring —
          # and "it fits" would be the dangerous direction to get wrong.
          { lookups: nil, over_limit: false }
        else
          { lookups: result.lookups, over_limit: result.permerror? && result.reason == :lookup_limit }
        end
      rescue StandardError => e
        warn_failure("lookup budget", e)
        { lookups: nil, over_limit: false }
      end

      # Does this record name the sender directly? Only a direct term counts
      # here — this decides which record supplies the merged `all`, and a record
      # that reaches the sender through somebody else's include is still THEIR
      # policy record.
      def ours?(record)
        Record.parse_terms(record).any? { |term| sender_term?(term) }
      end

      # Takes a Term, not a string: "does this name us" is a question about the
      # term's target, and Term already knows how to find one.
      def sender_term?(term)
        return false unless term.include? || term.redirect?

        target = term.target
        !target.nil? && @sender.covers?(target)
      end

      def same_terms?(a, b)
        a.to_s.split(/\s+/).map(&:downcase) == b.to_s.split(/\s+/).map(&:downcase)
      end

      def warn_failure(what, error)
        @logger&.warn("[MailerToGo::SPF] #{what} for #{@name} failed: #{error.message}")
      end

      def plan(action, **attrs)
        Plan.new({
          action: action,
          name: @name,
          record: @record,
          include_name: @include_name,
          existing_records: [],
          merged_record: nil,
          all_qualifier: nil,
          lookups: nil,
          lookup_limit: Authorization::MAX_DNS_LOOKUPS,
          over_lookup_limit: false,
          resolved: true,
          notes: @notes,
        }.merge(attrs))
      end
    end
  end
end
