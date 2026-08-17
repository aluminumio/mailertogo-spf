# frozen_string_literal: true

require "set"
require "mailertogo/spf/record"
require "mailertogo/spf/term"
require "mailertogo/spf/authorization"

module MailerToGo
  module SPF
    # Prices a published SPF record against the RFC 7208 §4.6.4 lookup budget,
    # term by term, and notes the chain defects found on the way.
    #
    # Why this is not Authorization. That class answers "does this record
    # authorise ME?", and §4.6.2 ends a receiver's evaluation at the first
    # mechanism that matches — so it deliberately counts only the lookups spent
    # up to the match. That is the right number for a gating decision (a record
    # whose match lands on term 10 of an 11-term record passes at every real
    # receiver, and calling it a permerror would be wrong) and the wrong number
    # for describing the record itself, where the question is what it costs a
    # receiver that has to evaluate ALL of it. That second number is what every
    # SPF checker reports and the one people compare against, and the two can
    # legitimately disagree about the same record — one authorises you at a cost
    # of 10 while itself costing 11 and being broken for everybody past your
    # include.
    #
    # So: walk the whole tree, charge every querying term, and hand back the
    # cost attached to the term that incurred it.
    #
    # Bounded three ways, because this is the sort of thing that ends up behind
    # an unauthenticated "check my domain" box resolving whatever a stranger
    # typed: the §4.6.4 cap itself, a depth limit, and a hard CEILING past which
    # we stop resolving — once a record is over budget the exact number no
    # longer changes what anyone should do about it.
    #
    # Reads DNS through the same injected resolver as everything else, so behind
    # a CachingResolver an audit of a name you have already authorised is
    # largely cache hits.
    class ChainAudit
      # RFC 7208 §4.6.4 — 10 is legal, 11 permerrors. The same cap Authorization
      # enforces; named here because this class reports against it.
      LIMIT = Authorization::MAX_DNS_LOOKUPS

      # Belt-and-suspenders against a pathological tree, exactly as in the
      # engine: the budget below is the real bound, this stops runaway recursion
      # on a wide shallow record.
      MAX_DEPTH = Authorization::MAX_DEPTH

      # Stop resolving well past the cap. A record needing 20 lookups and one
      # needing 200 are the same record to a receiver: permerror. Past this the
      # total is reported as a floor (see #capped?) rather than chased.
      CEILING = 2 * LIMIT

      attr_reader :hostname, :record, :terms, :total, :targets_without_spf, :duplicated_in_chain

      # record    — the record to price. Pass nil to have the apex resolved from
      #             DNS at `hostname`, which is the whole question ("what does
      #             this domain's SPF cost?") asked in one call.
      # hostname  — the name the record is published at. Guards a record that
      #             includes itself, and is where a nil record is resolved from.
      # resolver  — anything responding to #call(name); see Resolver.
      # term_class— a Term subclass to build the terms as, for a caller that
      #             hangs its own copy off a term.
      def self.call(hostname:, resolver:, record: nil, term_class: nil)
        new(hostname: hostname, resolver: resolver, record: record, term_class: term_class).run
      end

      def initialize(hostname:, resolver:, record: nil, term_class: nil)
        @record = record&.to_s
        @hostname = Record.normalize_name(hostname)
        @resolver = resolver
        @term_class = term_class || Term
        @spent = 0
        @total = nil
        @terms = []
        @targets_without_spf = []
        @duplicated_in_chain = []
        # nil until we resolve the apex ourselves — "cannot say", not "no".
        @apex_duplicated = nil
        @resolved = true
        @partial = false
        @capped = false
        # The queried name guards a record that includes itself.
        @seen = Set.new([@hostname])
      end

      def run
        resolve_apex if @record.nil?

        parsed = Record.parse_terms(@record, term_class: @term_class)
        # §6.1 — a record containing `all` ignores its redirect= outright,
        # wherever in the record the redirect sits.
        terminal = parsed.any?(&:all?)
        seen_all = false

        parsed.each do |term|
          unreachable = seen_all || (term.redirect? && terminal)
          # Rebuilt rather than mutated: unreachability is a fact about the
          # term's POSITION, which only this loop knows, and a term is frozen.
          term = @term_class.new(raw: term.raw, position: term.position, unreachable: unreachable)
          cost = unreachable ? 0 : charge(term, depth: 0)
          @terms << term.priced(lookups: cost, running_total: @spent)
          seen_all ||= term.all?
        end

        # nil, not 0, when there is nothing to price. 0 is a legitimate total —
        # `v=spf1 -all` costs exactly that — so using it for "no record" lets a
        # caller that skipped #published? report "this record costs 0 lookups"
        # about a domain with no record at all.
        @total = published? ? @spent : nil
        self
      end

      def limit = LIMIT

      # Is there a record here at all? False when the name publishes no v=spf1
      # record (or DNS did not answer — see #resolved?).
      def published? = !@record.to_s.empty?

      # Did DNS answer when we resolved the apex ourselves? Always true when the
      # record was handed to us. A resolver hiccup is not "this domain has no
      # SPF", and the two must never be reported as the same thing.
      def resolved? = @resolved

      # More than §4.6.4 allows: 10 is legal, 11 permerrors.
      def over_limit? = @total.to_i > LIMIT

      # Part of the chain did not resolve, so the total is a FLOOR. Never report
      # "this fits" from a count we could not finish — the direction that is
      # dangerous to get wrong is the reassuring one.
      def partial? = @partial

      # We stopped walking at CEILING: the record is far past the cap and the
      # real total is higher than the one reported. Same treatment as partial —
      # the number is a floor — for a different reason.
      def capped? = @capped

      # Was there more than one v=spf1 record at the hostname itself? §4.5 makes
      # that a permerror just as surely as duplicates inside the chain.
      #
      # nil means "cannot say" rather than "no": the record was handed to us, so
      # we never looked at the apex (or DNS did not answer). Only a caller that
      # let us resolve the apex gets a true/false here — the one that resolved it
      # already knows, and should report from what it saw rather than ask us.
      def apex_duplicated? = @apex_duplicated

      # How many lookups are still available before the cap, or nil when we
      # cannot say (a floor cannot answer "how much room is left", and neither
      # can a record that does not exist).
      def headroom
        return nil if partial? || capped? || !published?

        [LIMIT - @total.to_i, 0].max
      end

      private

      # No record was supplied: read the apex ourselves.
      def resolve_apex
        txts = @resolver.call(@hostname)
        if txts.nil?
          @resolved = false
          @partial = true
          @record = ""
          return
        end

        records = Array(txts).map { |t| Record.normalize_txt(t) }.select { |t| Record.spf_record?(t) }
        # §4.5 — two records at the apex permerror the evaluation just as surely
        # as two anywhere else in the chain. It is reported SEPARATELY from
        # `duplicated_in_chain` even so, because the apex is not *in* the chain:
        # it is the record being priced. Folding it in made the same domain audit
        # differently depending on whether the caller resolved the apex or we
        # did, and a caller that raises its own duplicate-record defect from the
        # records it resolved would then raise it twice.
        @apex_duplicated = records.size > 1
        # We price the first, because there has to be something to read.
        @record = records.first.to_s
      end

      # Spend the budget this term costs and return the amount.
      def charge(term, depth:)
        before = @spent
        if term.querying?
          @spent += 1
          # a / mx / ptr / exists cost exactly one query each and expand no
          # further; include: and redirect= pull in another record, and
          # everything in it.
          descend(term.target, depth) if term.include? || term.redirect?
        end
        @spent - before
      end

      def descend(target, depth)
        name = Record.normalize_name(target.to_s)
        return if name.empty?
        # Macros (%{i} etc., §7) are per-message: the lookup is charged, the
        # branch cannot be followed.
        return if name.include?("%")
        return if depth >= MAX_DEPTH
        return unless @seen.add?(name) # loop guard (§11.1)

        if @spent > CEILING
          @capped = true
          return
        end

        txts = @resolver.call(name)
        if txts.nil?
          @partial = true
          return
        end

        records = Array(txts).map { |t| Record.normalize_txt(t) }.select { |t| Record.spf_record?(t) }
        # §5.2 — an include: whose target publishes no SPF record is a permerror
        # for the whole evaluation, not a term that quietly does nothing.
        return @targets_without_spf << name if records.empty?
        # §4.5 — two records anywhere in the chain permerror the whole thing.
        return @duplicated_in_chain << name if records.size > 1

        walk(records.first, depth + 1)
      end

      def walk(record, depth)
        parsed = Record.parse_terms(record, term_class: @term_class)
        terminal = parsed.any?(&:all?)

        parsed.each do |term|
          break if term.all? # nothing after `all` is ever evaluated
          next if term.redirect? && terminal # §6.1

          charge(term, depth: depth)
        end
      end
    end
  end
end
