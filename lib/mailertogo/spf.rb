# frozen_string_literal: true

require "mailertogo/spf/version"
require "mailertogo/spf/record"
require "mailertogo/spf/term"
require "mailertogo/spf/hostname"
require "mailertogo/spf/sender"
require "mailertogo/spf/resolver"
require "mailertogo/spf/result"
require "mailertogo/spf/authorization"
require "mailertogo/spf/chain_audit"
require "mailertogo/spf/plan"
require "mailertogo/spf/merge_plan"

module MailerToGo
  # An SPF engine that reads a record the way a receiving MTA does: it resolves
  # the include chain, stops where the receiver stops, and counts DNS lookups
  # against the RFC 7208 §4.6.4 cap.
  #
  # Three questions, three entry points:
  #
  #   MailerToGo::SPF.authorize("example.com")
  #     → does this domain's published SPF authorize me?
  #
  #   MailerToGo::SPF.merge_plan("example.com")
  #     → what should I tell them to publish, given what is already there?
  #
  #   MailerToGo::SPF.chain_audit("example.com")
  #     → what does this record cost a receiver, term by term?
  #
  # Both take `include:` (the mechanism you want authorized) and `aliases:`
  # (other names that mean the same sender). Both default to MailerToGo's own
  # names, so the zero-argument form is the useful one for MailerToGo customers
  # and one keyword makes it work for anybody else:
  #
  #   MailerToGo::SPF.authorize("example.com", include: "spf.example.net")
  module SPF
    # MailerToGo publishes an outer alias and a leaf. Customers are told to
    # include the leaf, but either one authorizes us, so both count as "me".
    DEFAULT_INCLUDE = "_spf.mailertogo.net"
    DEFAULT_ALIASES = ["mailertogo.net"].freeze

    class << self
      # Process-wide defaults. Everything here can also be passed per call.
      #
      #   MailerToGo::SPF.configure do |c|
      #     c.include  = "spf.example.net"
      #     c.aliases  = ["example.net"]
      #     c.resolver = MailerToGo::SPF::CachingResolver.new(MailerToGo::SPF::Resolver.new)
      #     c.logger   = Logger.new($stdout)
      #   end
      attr_accessor :logger
      attr_writer :include, :aliases, :resolver

      def include_name
        defined?(@include) && @include ? @include : DEFAULT_INCLUDE
      end

      def aliases
        defined?(@aliases) && @aliases ? @aliases : DEFAULT_ALIASES
      end

      # Resolving is I/O, so the default is built once and shared. Pass your own
      # (any object responding to #call(name)) to change how DNS happens.
      def resolver
        @resolver ||= Resolver.new
      end

      def configure
        yield self
        self
      end

      # Does <hostname>'s published SPF authorize the sender?
      # Returns a Result (see result.rb) — never raises for a DNS failure.
      #
      # published: evaluates a supplied record as if it were published at
      # <hostname>, which is how you price a record that does not exist yet.
      def authorize(hostname, include: nil, aliases: nil, resolver: nil,
                    sender: nil, published: nil, logger: nil)
        sender ||= sender_for(include || include_name, aliases)
        raise ArgumentError, "no include name given or configured" if sender.nil?

        Authorization.call(
          hostname,
          sender: sender,
          resolver: resolver || self.resolver,
          published: published,
          logger: logger || self.logger
        )
      end

      # What should this domain publish, given what is already at that name?
      # Returns a Plan (see plan.rb).
      #
      # record: the standalone record you would otherwise hand them; defaults to
      # the sender's own `v=spf1 include:… ~all`.
      def merge_plan(name, record: nil, include: nil, aliases: nil, resolver: nil,
                     sender: nil, authorization: nil, logger: nil)
        # A record with no include mechanism gives us no identity to merge in —
        # hand back a null plan rather than inventing one.
        sender ||= sender_for(include || (record.nil? ? include_name : Record.include_target(record)), aliases)
        return Plan.none(name: name, record: record) if sender.nil?

        MergePlan.call(
          name,
          record: record || sender.record,
          sender: sender,
          resolver: resolver || self.resolver,
          authorization: authorization,
          logger: logger || self.logger
        )
      end

      # What does this record cost a receiver that evaluates all of it?
      # Returns a ChainAudit (see chain_audit.rb).
      #
      # This is a different number from Result#lookups and is meant to be: the
      # authorization walk stops where the receiver stops (§4.6.2), while this
      # prices the whole tree against the §4.6.4 budget — the number other SPF
      # checkers report. Notably sender-agnostic; there is no `include:` here,
      # because the record's cost has nothing to do with who is asking.
      #
      # record: price this record instead of resolving one at `hostname`, which
      # is how you price a record that is not published yet.
      def chain_audit(hostname, record: nil, resolver: nil, term_class: nil)
        ChainAudit.call(hostname: hostname, record: record, resolver: resolver || self.resolver,
                        term_class: term_class)
      end

      # Is this untrusted input something we should resolve at all? Returns the
      # normalized hostname, or nil. See hostname.rb — it is a gate, kept
      # separate from the entry points above on purpose, because "that is not a
      # hostname" is a fact about the INPUT and must not be dressed up as a fact
      # about somebody's DNS.
      def normalize_hostname(input) = Hostname.parse(input)
      def hostname?(input) = Hostname.valid?(input)

      # The names that mean "me". Public because a caller that asks both
      # questions about the same sender should build it once.
      def sender(include: nil, aliases: nil)
        sender_for(include || include_name, aliases)
      end

      private

      # nil when there is no name to build a sender out of.
      #
      # The alias default is deliberately narrow: the configured aliases belong
      # to the configured include, so asking about somebody else's include with
      # no aliases of its own gets exactly that one name, not ours.
      def sender_for(name, aliases)
        name = name.to_s.strip
        return nil if name.empty?

        if aliases.nil?
          aliases = Record.normalize_name(name) == Record.normalize_name(include_name) ? self.aliases : []
        end
        Sender.new(name, aliases: aliases)
      end
    end
  end
end
