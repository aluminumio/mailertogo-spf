# frozen_string_literal: true

require "mailertogo/spf/record"

module MailerToGo
  module SPF
    # One term of an SPF record: what it is, and what it costs.
    #
    # `Record` reads the raw text — split a record into terms, strip a
    # qualifier, name a mechanism. This is the same knowledge asked as
    # questions instead of pattern-matched at every call site: `term.include?`,
    # `term.querying?`, `term.unreachable?`. Nothing here re-parses what
    # `Record` already parses; it builds on it, which is the only way two
    # readings of the same term cannot drift apart.
    #
    # Deliberately NOT here: any English sentence about what a term means to a
    # human. A description is product voice — it belongs to whoever is writing
    # to their own customers, in their own words, and no gem should be in the
    # business of writing it. What a consumer wants is a place to hang that
    # copy, so `Term` is designed to be subclassed: every predicate it answers
    # is a predicate your sentence can switch on, and both #priced and
    # `Record.parse_terms(record, term_class:)` build your subclass rather than
    # this class.
    #
    #   class AnnotatedTerm < MailerToGo::SPF::Term
    #     def meaning
    #       return "Everything not matched above is marked, not rejected." if all? && qualifier == "~"
    #       …
    #     end
    #   end
    #
    # Immutable, and frozen on construction: pricing a term builds a copy via
    # #priced rather than mutating it, so a term can never be observed
    # half-priced.
    class Term
      # RFC 7208 §4.6.4 — the mechanisms that cost a DNS query. The lookup
      # budget is a count of these (plus the redirect= modifier).
      QUERYING = %w[include a mx ptr exists].freeze

      # §4.6.2 — the qualifier a mechanism may carry, and what a match under it
      # means. "+" when absent.
      QUALIFIERS = { "+" => :pass, "-" => :fail, "~" => :softfail, "?" => :neutral }.freeze

      # Every mechanism SPF defines. Anything else in mechanism position is a
      # syntax error (see #unknown?), not a term that quietly does nothing.
      MECHANISMS = (QUERYING + %w[ip4 ip6 all]).freeze

      # A modifier (`redirect=`, `exp=`, or an unknown one) rather than a
      # mechanism. Modifiers are name=value and position-independent (§4.6.1).
      MODIFIER = /\A([a-z][a-z0-9\-_.]*)=(.*)\z/i

      # `all`, with whatever junk is glued onto it. The junk is real and
      # surprisingly common — records ending `~all;google-site-verification=…`
      # exist in the wild, where the `;`-joined fragment is not a valid SPF term
      # at all. Matching it HERE is what keeps such a record's terminal term
      # recognised as an `all` (which ends evaluation, and whose qualifier is
      # the domain's policy) rather than filed as junk and the record read as
      # having no `all` whatsoever.
      ALL = /\Aall([^a-z0-9].*)?\z/i

      attr_reader :raw, :position, :qualifier, :lookups, :running_total

      # raw           — the term exactly as published.
      # position      — 1-based index in the record; 0 when it was not parsed as
      #                 part of one. For display, and for nothing else.
      # unreachable   — the term is never evaluated: it sits after `all`, or it
      #                 is a redirect= in a record that has an `all`
      #                 (§5.1/§6.1). Such a term authorises nothing and costs
      #                 nothing.
      # lookups       — DNS lookups this term costs a receiver: itself, plus
      #                 everything the record it pulls in costs. nil until
      #                 priced by ChainAudit.
      # running_total — the record's cumulative cost through this term.
      def initialize(raw:, position: 0, unreachable: false, lookups: nil, running_total: nil)
        @raw = raw.to_s
        @position = position
        @unreachable = unreachable
        @lookups = lookups
        @running_total = running_total
        @bare = Record.strip_qualifier(@raw)
        @qualifier = Record.qualifier_of(@raw)
        @modifier_match = MODIFIER.match(@bare)
        @all_match = ALL.match(@bare)
        @mechanism = @modifier_match ? nil : Record.mechanism_of(@bare)
        freeze
      end

      # A copy carrying the cost ChainAudit measured. `self.class` so a
      # subclass that adds its own copy stays that subclass through pricing.
      def priced(lookups:, running_total:)
        self.class.new(raw: raw, position: position, unreachable: unreachable?,
                       lookups: lookups, running_total: running_total)
      end

      # ── What it is ────────────────────────────────────────────────────────

      # "include", "ip4", "all"… nil for a modifier or for junk.
      def mechanism
        return "all" if @all_match

        @mechanism if MECHANISMS.include?(@mechanism)
      end

      # "redirect", "exp", or another modifier name; nil for a mechanism.
      def modifier
        @modifier_match && @modifier_match[1].downcase
      end

      # The value after the ":" or "=" — an include target, an IP range, an
      # explanation name. nil for a bare `a`, `mx` or `all`.
      def target
        value = @modifier_match ? @modifier_match[2] : @bare.split(":", 2)[1]
        value.to_s.empty? ? nil : value
      end

      # :pass | :fail | :softfail | :neutral — what a match under this
      # qualifier means to a receiver (§4.6.2). On the terminal `all` this is
      # the domain's whole policy for unauthorised mail (§5.1).
      def qualifier_meaning = QUALIFIERS[@qualifier || "+"]

      def all? = mechanism == "all"
      def include? = mechanism == "include"
      def redirect? = modifier == "redirect"
      def ip? = %w[ip4 ip6].include?(mechanism)

      # Does this term spend from the §4.6.4 budget at all?
      def querying? = QUERYING.include?(mechanism) || redirect?

      # Never evaluated by a receiver, so it authorises nothing and costs
      # nothing. Set by whoever read the record in order (ChainAudit); a term
      # on its own cannot know what precedes it.
      def unreachable? = @unreachable == true

      # Not a mechanism SPF defines and not a modifier: junk. Per §4.6 a syntax
      # error in a record permits a receiver to permerror the whole thing, so
      # this is never harmless.
      def unknown? = mechanism.nil? && modifier.nil?

      # Which of the three a term is: a named mechanism, "modifier", "unknown".
      def kind
        return "modifier" if modifier
        return "unknown" if unknown?

        mechanism
      end

      # The junk glued onto an `all` (`~all;google-site-verification=…`), or
      # nil. Worth surfacing: it is inside the record rather than beside it, so
      # it is not the second TXT record its author thought they were writing.
      def all_suffix
        suffix = @all_match && @all_match[1].to_s.strip
        suffix.to_s.empty? ? nil : suffix
      end

      def to_s = raw
    end
  end
end
