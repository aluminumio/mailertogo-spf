# frozen_string_literal: true

require "mailertogo/spf/record"
require "mailertogo/spf/authorization"

module MailerToGo
  module SPF
    # What to tell a domain owner to publish, given what is already at that name.
    #
    # action:
    #   :publish     — nothing SPF-shaped is published at this name: hand them
    #                  the standalone record. Also the fallback when DNS did not
    #                  answer (resolved? == false), because guessing is worse.
    #   :merge       — one record is already there and does not authorize the
    #                  sender: they must REPLACE it with merged_record.
    #   :deduplicate — two or more v=spf1 records are already published (the
    #                  RFC 7208 §3.2 violation): replace ALL of them with
    #                  merged_record.
    #   :satisfied   — a single record already reaches the sender. Nothing to say.
    #
    # over_lookup_limit is true only when the merged record was definitively
    # measured past RFC 7208 §4.6.4's cap — never on an inconclusive DNS answer.
    Plan = Struct.new(:action, :name, :record, :include_name, :existing_records,
                      :merged_record, :all_qualifier, :lookups, :lookup_limit,
                      :over_lookup_limit, :resolved, :notes, keyword_init: true) do
      def publish? = action == :publish
      def merge? = action == :merge
      def deduplicate? = action == :deduplicate
      def satisfied? = action == :satisfied

      # Are we asking them to REPLACE an existing record rather than add one?
      # The difference matters enormously in a UI: "add this TXT record" next to
      # an existing SPF record is exactly the instruction that produces the
      # two-record permerror in the first place.
      def replacement? = merge? || deduplicate?

      # Already in the RFC-violating two-record state right now.
      def duplicated? = deduplicate?

      def over_limit? = over_lookup_limit == true

      def resolved? = resolved == true

      # The line to actually put in front of them. Withheld when merging would
      # blow the lookup budget: a record we know permerrors is worse than the
      # standalone instruction plus an explanation of what has to go first.
      def offered_record
        return nil unless replacement?

        over_limit? ? nil : merged_record
      end

      # Is this state something to ALERT them about, or just an instruction?
      # Already-duplicated and over-the-cap are defects they are living with
      # today; a plain merge is just telling them how to add the sender
      # correctly the first time. A fact about the plan, not about the view —
      # two surfaces must not have to agree on it independently.
      def warning? = duplicated? || over_limit?
      def severity = warning? ? :warning : :info

      # ── What one row of a "publish these DNS records" table should show ──
      #
      # Asking the plan reconciles the row against the instruction in ONE place.
      # A view doing it itself re-derives the decision to withhold
      # (offered_record) that the plan has already made, and the two can drift.

      # Does this row carry the merged replacement instead of its own value?
      # Only the SPF row at the name we resolved, and only when a merged line is
      # actually on offer (never when it is withheld for the lookup cap).
      def replaces?(name:, value:)
        offered = offered_record
        return false if offered.nil? || offered.empty?
        return false unless value.to_s.start_with?("v=spf1")

        Record.normalize_name(name) == self.name
      end

      def value_for(name:, value:)
        replaces?(name: name, value: value) ? offered_record : value
      end

      # The "no instruction beyond the standalone record" plan, so no caller has
      # to nil-check before asking a question. It answers everything the way a
      # real :publish plan does: nothing to replace, nothing to warn about.
      def self.none(name: nil, record: nil)
        new(action: :publish, name: name && Record.normalize_name(name), record: record,
            existing_records: [], notes: [], resolved: false,
            lookup_limit: Authorization::MAX_DNS_LOOKUPS, over_lookup_limit: false)
      end
    end
  end
end
