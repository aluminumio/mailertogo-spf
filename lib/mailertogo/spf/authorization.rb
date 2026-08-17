# frozen_string_literal: true

require "set"
require "mailertogo/spf/record"
require "mailertogo/spf/term"
require "mailertogo/spf/result"
require "mailertogo/spf/sender"

module MailerToGo
  module SPF
    # Answers one question the way a receiving MTA would: does <hostname>'s
    # published SPF actually authorize this sender?
    #
    # Why resolve at all, instead of string-matching the record? Because SPF is
    # a TREE, not a string. The obvious implementation — "does the apex record
    # contain the literal token `include:_spf.mailertogo.net`" — reports a false
    # failure against every customer who publishes an outer alias:
    #
    #   example.com          TXT  v=spf1 include:spf.hosting.example include:mailertogo.net ~all
    #   mailertogo.net       TXT  v=spf1 include:_spf.mailertogo.net ~all
    #   _spf.mailertogo.net  TXT  v=spf1 ip4:… ip4:… ~all
    #
    # That record passes SPF at every real receiver. A literal match calls it a
    # failure, and anything gated on the answer — verification state, drift
    # alerts, the ability to send — goes wrong with it. So we RESOLVE the chain:
    # follow `include:` (and the `redirect=` modifier) until we reach a name the
    # sender owns, or an ip4/ip6 mechanism covering the sender's addresses.
    #
    # RFC 7208 §4.6.4 caps an evaluation at 10 DNS-querying mechanisms; past
    # that a receiver returns PERMERROR and the record does NOT pass. We enforce
    # the same cap rather than silently passing a record real receivers reject —
    # and it doubles as the bound that stops a hostile record walking us into an
    # unbounded crawl.
    #
    # The cap counts the terms an evaluation actually EVALUATES, and §4.6.2 ends
    # the evaluation at the first mechanism that MATCHES — so we walk terms in
    # record order and stop at the match, exactly where a receiver stops.
    # Counting the whole tree instead reports a false permerror for the very
    # common record whose match lands on term 10 of an 11-term record: inside
    # budget, and passing at every real receiver.
    class Authorization
      # RFC 7208 §4.6.4 — mechanisms that cost a DNS query (include/a/mx/ptr/
      # exists) plus the redirect modifier, summed over the terms EVALUATED
      # before the match. "MUST limit ... to 10" makes exactly 10 legal:
      # 10 passes, 11 permerrors.
      MAX_DNS_LOOKUPS = 10

      # Belt-and-suspenders against a pathological tree; the lookup budget above
      # is the real bound, this just stops runaway recursion on a wide shallow
      # record.
      MAX_DEPTH = 10

      # Mechanisms that consume one DNS lookup from the budget above, and the
      # §4.6.2 qualifier map (here only ever read off the record's terminal
      # `all` — see Result#all_qualifier). Both are RFC anatomy and live on
      # Term, which is where a caller goes to ask what a term IS; named here
      # because this is where they are spent.
      QUERYING_MECHANISMS = Term::QUERYING
      ALL_QUALIFIERS = Term::QUALIFIERS

      # hostname  — the domain whose SPF we are reading.
      # sender    — a Sender: the names that mean "me".
      # resolver  — anything responding to #call(name); see Resolver.
      # published — evaluate this record AS IF it were published at hostname,
      #             instead of whatever DNS says is there. The only way to ask
      #             "what would this cost a receiver?" of a line that is not
      #             published yet; MergePlan prices its merged record with it.
      #             Everything below the apex still resolves from real DNS.
      # logger    — optional, anything responding to #warn.
      def self.call(hostname, sender:, resolver:, published: nil, logger: nil)
        new(hostname, sender: sender, resolver: resolver, published: published, logger: logger).run
      end

      # The sending addresses a sender authorizes, read from its own leaf record
      # — the same record `include:_spf.mailertogo.net` resolves to. Used to
      # DETECT a customer who hardcoded those addresses (:pinned), not to bless
      # it. Resolved separately from the customer's walk so it never costs them
      # lookup budget.
      def self.sending_nets(sender, resolver)
        txts = resolver.call(sender.include_name)
        record = Array(txts).map { |t| Record.normalize_txt(t) }.find { |t| Record.spf_record?(t) }
        return [] if record.nil? || record.empty?

        Record.ip_nets(Record.terms(record))
      end

      def initialize(hostname, sender:, resolver:, published: nil, logger: nil)
        @host = Record.normalize_name(hostname)
        @sender = sender
        @lookup = resolver
        @logger = logger
        @published = published.to_s.empty? ? nil : published.to_s
        @want = sender.include_name
        @seen = Set.new([@host])
        @lookups = 0
        @dns_error = false
        @permerror = nil
        @matched = nil
        @matched_directly = false
        @match_at = nil
        # [IPAddr, lookups spent before that term] — the second half is what
        # lets us charge a pinned record only the lookups a receiver does
        # before it stops.
        @customer_nets = []
        @ip_pinned = nil
        @ip_coverage = nil
        @ip_match_at = nil
        @all_qualifier = nil
      end

      def run
        records, err = apex_records
        return unknown("DNS lookup for #{@host} failed") if err == :error

        if records.size > 1
          # RFC 7208 §4.5: more than one v=spf1 record is a PERMERROR — no
          # evaluation happens at all. We still scan every one of them for the
          # sender's include so the result can say "broken, but my record IS
          # published" (see #matched).
          records.each { |r| note_sender_names(Record.terms(r), 0) }
          return permerror(:duplicate_records,
                           "#{@host} publishes more than one v=spf1 record — receivers " \
                           "return permerror (RFC 7208 §4.5) and no SPF passes for this domain")
        end

        record = records.first
        return failure("No v=spf1 record on #{@host}") if record.nil?

        walk(record, depth: 0, authoritative: true)
        match_by_ip! if @match_at.nil?

        # Over budget beats everything: receivers PERMERROR such a record, so it
        # does not pass even when the sender's include is sitting right there in
        # it. What counts is the budget spent up to the MATCH (see #budget_used),
        # not the size of the tree — terms after the match are never evaluated
        # by anyone.
        if budget_used > MAX_DNS_LOOKUPS
          return permerror(:lookup_limit,
                           "#{@host}'s SPF needs more than #{MAX_DNS_LOOKUPS} DNS lookups " \
                           "(RFC 7208 §4.6.4) — receivers return permerror and the record never passes")
        end

        return permerror(*@permerror) if @permerror
        return pass if @match_at
        return pinned if @ip_pinned
        return unknown("SPF chain for #{@host} could not be fully resolved (DNS lookup failed)") if @dns_error

        failure("#{@host}'s SPF does not authorize #{@want} — resolved the full include chain " \
                "(#{pluralize(@lookups, "DNS lookup")}) and #{@want} is not in it#{all_clause}")
      end

      private

      # A supplied record stands in for the apex answer (see .call's `published:`);
      # its includes still resolve against live DNS below.
      def apex_records
        return spf_records_at(@host) if @published.nil?

        [[Record.normalize_txt(@published)].select { |t| Record.spf_record?(t) }, nil]
      end

      # Runaway guard for the crawl itself. The verdict uses #budget_used.
      def over_budget? = @lookups > MAX_DNS_LOOKUPS

      # The number a receiver measures against the §4.6.4 cap: DNS-querying
      # terms evaluated up to and including the one that matched (§4.6.2 ends
      # evaluation there). Only when nothing matches does the whole walk count.
      # A record whose match lands on term 10 of an 11-term record spends 10 and
      # passes; counting every node in the tree would spend 11 and permerror it.
      def budget_used = @match_at || @ip_match_at || @lookups

      # Walk one record's terms IN ORDER, descending into includes/redirects,
      # exactly as far as a receiver would: evaluation stops at the first
      # mechanism that matches (@match_at), at `all` (which always matches), and
      # at the lookup budget. Collects ip4/ip6 terms as we go so a record that
      # authorizes the sender's addresses directly still matches.
      #
      # `authoritative` marks the records whose `all` decides the domain's
      # answer — the apex and anything it redirect=s to, never an include's (an
      # included record's `all` never leaves that include, §5.2).
      def walk(record, depth:, authoritative: false)
        terms = Record.terms(record)
        note_sender_names(terms, depth)
        redirect = nil

        terms.each do |term|
          break if @match_at # §4.6.2 — evaluation ends at the first matching mechanism

          qualifier = Record.qualifier_of(term)
          t = Record.strip_qualifier(term)

          if (target = t[/\Aredirect=(.+)\z/i, 1])
            # A modifier, not a mechanism: it is evaluated only after every
            # mechanism has failed to match (§6.1), so hold it until the loop
            # is done.
            redirect = target
            next
          end

          mechanism = Record.mechanism_of(t)
          case mechanism
          when "all"
            # `all` matches everything, so nothing after it is ever evaluated
            # and any redirect= in the same record is ignored outright (§6.1).
            @all_qualifier ||= ALL_QUALIFIERS.fetch(qualifier || "+", :pass) if authoritative
            # Leaves #walk, not just the loop: a pending redirect= must be
            # abandoned too, which a `break` would not do.
            return # rubocop:disable Lint/NonLocalExitFromIterator
          when "ip4", "ip6"
            @customer_nets.concat(Record.ip_nets([t]).map { |net| [net, @lookups] })
          when *QUERYING_MECHANISMS
            break if over_budget?

            if mechanism == "include"
              descend(t.split(":", 2).last, depth)
            else
              # a / mx / ptr / exists cost budget but cannot name the sender —
              # a sending service publishes an include target, never an a/mx
              # mechanism a customer would borrow.
              @lookups += 1
            end
          end
        end

        return if redirect.nil? || @match_at || over_budget?

        # Nothing matched: the redirect target's evaluation replaces this
        # record's, its `all` included.
        descend(redirect, depth, authoritative: authoritative)
      end

      # Free pass over a record's terms (no DNS) noting whether it names the
      # sender. Done before the budget-limited expansion below so that a record
      # which blows the 10-lookup cap STILL tells us the customer published the
      # include — gating callers need that distinction so they do not un-verify
      # a domain whose only sin is an over-long chain.
      def note_sender_names(terms, depth)
        terms.each do |term|
          t = Record.strip_qualifier(term)
          target = t[/\Ainclude:(.+)\z/i, 1] || t[/\Aredirect=(.+)\z/i, 1]
          next if target.nil? || target.empty?

          name = Record.normalize_name(target)
          next unless @sender.covers?(name)
          next unless @matched.nil?

          @matched = name
          @matched_directly = depth.zero?
        end
      end

      def descend(target, depth, authoritative: false)
        @lookups += 1
        name = Record.normalize_name(target.to_s)
        return if name.empty?

        if @sender.covers?(name)
          if @matched.nil?
            @matched = name
            @matched_directly = depth.zero?
          end
          # The mechanism that ended the evaluation, and the budget it had spent
          # by then — the only count §4.6.4 measures.
          @match_at = @lookups
          return # no need to resolve the sender's own record; we know what it authorizes
        end

        # Macro expansion (%{i} etc., §7) is per-message and cannot be evaluated
        # here; the lookup is counted, the branch is simply not followed.
        return if name.include?("%")
        return if depth >= MAX_DEPTH
        return unless @seen.add?(name) # loop guard (RFC 7208 §11.1 include loops)
        return if over_budget?

        records, err = spf_records_at(name)
        @dns_error = true if err == :error

        if records.size > 1
          # A duplicate-record PERMERROR anywhere in the chain permerrors the
          # whole evaluation for the receiver, so it fails the domain too.
          records.each { |r| note_sender_names(Record.terms(r), depth + 1) }
          @permerror ||= [:duplicate_records,
                          "#{name} (included by #{@host}) publishes more than one v=spf1 record, " \
                          "which makes the whole evaluation permerror (RFC 7208 §4.5)",]
          return
        end

        return if records.first.nil?

        walk(records.first, depth: depth + 1, authoritative: authoritative)
      end

      # [records_array, error_or_nil] — error is :error when DNS itself failed.
      # More than one record is left for the caller to classify (RFC 7208 §4.5).
      def spf_records_at(name)
        txts = @lookup.call(name)
        return [[], :error] if txts.nil?

        [Array(txts).map { |t| Record.normalize_txt(t) }.select { |t| Record.spf_record?(t) }, nil]
      end

      # A customer who lists the sender's addresses directly instead of
      # including it is NOT equivalently authorized, and reporting that as a
      # clean pass is a trap. Sending addresses move — relay nodes rotate,
      # address ranges are added and retired — and the entire point of
      # publishing an include target is that an include inherits those changes
      # for free. A pinned record instead (a) silently stops authenticating the
      # day an address moves, with no signal to anyone, and (b) keeps
      # authorizing an address after the sender releases it, which may later
      # belong to somebody else entirely. So: detect it, give it its own
      # :pinned status, and tell them to switch.
      def match_by_ip!
        return if @customer_nets.empty?

        ours = self.class.sending_nets(@sender, @lookup)
        return if ours.empty?

        # "Covered" = the customer's term authorizes one of the sender's ranges
        # in full. "Touched" also counts a term that names only part of a range
        # (one address out of a /24, say) — already-partial pinning, the most
        # brittle shape of all, and the one most worth surfacing.
        covered = ours.count { |o| @customer_nets.any? { |c, _at| covers?(c, o) } }
        touched = ours.count { |o| @customer_nets.any? { |c, _at| covers?(c, o) || covers?(o, c) } }
        return if touched.zero?

        @ip_pinned = covered == ours.size ? :pinned_full : :pinned_partial
        @ip_coverage = [touched, ours.size]
        # An ip mechanism covering the sending address ends the receiver's
        # evaluation right there (§4.6.2), so a pinned record is charged only
        # the lookups spent BEFORE that term — a long chain sitting behind the
        # pin never makes it permerror.
        @ip_match_at = @customer_nets.filter_map do |c, at|
          at if ours.any? { |o| covers?(c, o) || covers?(o, c) }
        end.min
      end

      def covers?(outer, inner)
        outer.include?(inner)
      rescue StandardError
        false # mismatched families (ip4 vs ip6) etc.
      end

      def pass
        detail = if @matched_directly
                   "SPF includes #{@matched}"
                 else
                   "SPF reaches #{@matched} through its include chain (#{pluralize(@lookups, "DNS lookup")})"
                 end
        result(:pass, detail: detail)
      end

      def pinned
        touched, total = @ip_coverage
        detail = if @ip_pinned == :pinned_full
                   "SPF lists #{@want}'s sending IP ranges directly (all #{total}) but never includes " \
                     "#{@want} — it authenticates today and stops silently the next time those IPs change"
                 else
                   "SPF lists #{@want}'s sending IPs directly and covers only #{touched} of the #{total} " \
                     "current ranges, and never includes #{@want} — mail from the rest already fails SPF"
                 end
        # A pinned record's `matched` stays nil: the include is NOT published in it.
        Result.new(status: :pinned, reason: @ip_pinned, detail: detail,
                   lookups: budget_used, all_qualifier: @all_qualifier, partial: @dns_error)
      end

      def failure(detail) = result(:fail, detail: detail)
      def unknown(detail) = result(:unknown, detail: detail)
      def permerror(reason, detail) = result(:permerror, detail: detail, reason: reason)

      def result(status, detail:, reason: nil)
        Result.new(status: status, reason: reason, detail: detail, matched: @matched,
                   lookups: budget_used, all_qualifier: @all_qualifier, partial: @dns_error)
      end

      # RFC 7208 §5.1: the terminal `all` decides what a receiver does with mail
      # from a domain whose record does not authorize the sender. `-all` is an
      # instruction to REJECT it; `~all` (much more common) only marks it. Same
      # defect, materially different urgency — so say which one they published.
      def all_clause
        case @all_qualifier
        when :fail then ". Its -all tells receivers to reject that mail outright"
        when :softfail then ". Its ~all means receivers mark that mail rather than rejecting it"
        else ""
        end
      end

      def pluralize(count, word)
        "#{count} #{word}#{"s" unless count == 1}"
      end
    end
  end
end
