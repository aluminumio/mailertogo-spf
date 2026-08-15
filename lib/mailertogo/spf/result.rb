# frozen_string_literal: true

module MailerToGo
  module SPF
    # The answer to "does this domain's published SPF authorise me?", shaped so
    # callers ask it questions rather than pattern-match a hash.
    #
    # status — :pass | :pinned | :fail | :permerror | :unknown
    #
    #   :pass      — the sender is reachable from the record, directly or
    #                through its include chain: durable authorisation.
    #   :pinned    — no include chain to the sender, but the record hardcodes
    #                the sender's current sending addresses. Mail passes SPF
    #                *today* and breaks silently the moment an address moves,
    #                so this is deliberately NOT :pass. See #pinned?.
    #   :fail      — the chain resolved fine; the sender simply is not in it.
    #   :permerror — the record is broken (duplicate records, or past the
    #                §4.6.4 lookup cap). Receivers reject it, so nothing passes.
    #   :unknown   — DNS did not answer. Verdict withheld, NOT a failure.
    #
    # The four-valued status exists so a resolver hiccup can never be mistaken
    # for "this domain removed my record". Anything that gates a customer on SPF
    # has to be able to tell those apart.
    #
    # reason narrows :permerror (:duplicate_records | :lookup_limit) and :pinned
    # (:pinned_full | :pinned_partial).
    #
    # all_qualifier (:pass | :fail | :softfail | :neutral | nil) is what the
    # record tells receivers to do with mail it does NOT authorise — the
    # qualifier on its terminal `all` (RFC 7208 §5.1). It is deliberately a
    # FIELD rather than a fifth status: the yes/no decision ("is my include
    # published?") is identical either way, but a `~all` domain's unauthorised
    # mail is merely marked while a `-all` domain's is rejected outright, and
    # the customer's remedy is far more urgent in the second case. Callers that
    # write to humans need to say which one they published.
    #
    # partial is true when part of the chain did not resolve, which makes
    # `lookups` a FLOOR rather than the real cost. Harmless for the verdict — a
    # match is a match — but it matters to anyone pricing a record against the
    # §4.6.4 budget, who must not report "this fits" from a count it could not
    # finish.
    Result = Struct.new(:status, :reason, :detail, :matched, :lookups,
                        :all_qualifier, :partial, keyword_init: true) do
      def pass? = status == :pass
      def pinned? = status == :pinned
      def permerror? = status == :permerror
      def unknown? = status == :unknown
      def failed? = %i[fail permerror].include?(status)
      def partial? = partial == true

      # Unauthorised, but under a `~all`: receivers mark the mail rather than
      # rejecting it, so the domain is in a materially better position than a
      # `-all` :fail. Same defect, different urgency.
      def softfail? = status == :fail && all_qualifier == :softfail

      # The record IS broken for receivers, but the sender's include is sitting
      # in it. Gating callers use this to avoid treating "the customer's SPF has
      # an unrelated RFC problem" as "the customer removed my record" — the
      # remedy is completely different, and un-verifying them is wrong.
      def permerror_with_sender_published? = permerror? && !matched.to_s.empty?

      # Which defect to tell the customer about, or nil when the record is
      # clean: :ip_pinned | :lookup_limit | :duplicate_records.
      def defect
        case status
        when :pinned then :ip_pinned
        when :permerror then reason == :lookup_limit ? :lookup_limit : :duplicate_records
        end
      end
    end
  end
end
