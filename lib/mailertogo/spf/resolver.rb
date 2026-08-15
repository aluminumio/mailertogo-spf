# frozen_string_literal: true

require "resolv"
require "mailertogo/spf/record"

module MailerToGo
  module SPF
    # The DNS seam.
    #
    # A resolver is anything that responds to `#call(name)` and returns:
    #
    #   [String, …] — the TXT strings published at that name
    #   []          — the name exists but has no TXT (or does not exist at all):
    #                 a definitive "nothing here"
    #   nil         — DNS did not answer (timeout, SERVFAIL, refused):
    #                 inconclusive, verdict withheld
    #
    # That three-way return is the whole contract, and the nil is the important
    # part: a resolver hiccup must never be reported as "this domain does not
    # authorise you". Everything in this gem funnels a nil into an :unknown
    # result rather than a :fail.
    #
    # A plain lambda satisfies the contract, which is how the test suite runs
    # with no network at all:
    #
    #   zone = { "example.com" => ["v=spf1 include:_spf.mailertogo.net ~all"] }
    #   MailerToGo::SPF.authorize("example.com", resolver: ->(n) { zone.fetch(n, []) })
    #
    # The default below uses Ruby's stdlib Resolv::DNS, so the gem has no runtime
    # dependencies. If you already speak DNS-over-HTTPS (or hold a resolver pool,
    # or want per-request caching), pass your own — see the README.
    class Resolver
      DEFAULT_TIMEOUT = 3

      # timeout      — seconds per nameserver attempt.
      # nameservers  — override the system resolvers, e.g. %w[1.1.1.1 8.8.8.8].
      def initialize(timeout: DEFAULT_TIMEOUT, nameservers: nil)
        @timeout = timeout
        @nameservers = nameservers
      end

      def call(name)
        query = Record.normalize_name(name)
        return [] if query.empty?

        dns = @nameservers ? ::Resolv::DNS.new(nameserver: Array(@nameservers)) : ::Resolv::DNS.new
        dns.timeouts = @timeout
        begin
          dns.getresources(query, ::Resolv::DNS::Resource::IN::TXT).map { |r| r.strings.join }
        ensure
          dns.close
        end
      rescue ::Resolv::ResolvError
        # Resolv collapses NXDOMAIN and "no information" into one error, so this
        # is the conservative reading: the name published nothing. A resolver
        # that can see the rcode (DoH, for instance) should return nil for
        # SERVFAIL and [] only for NXDOMAIN/NODATA — see the README.
        []
      rescue StandardError
        # Timeouts (Resolv::ResolvTimeout) and everything else unexpected:
        # inconclusive, never a failure.
        nil
      end
    end

    # Wraps any resolver in a small TTL cache.
    #
    # Resolving an SPF chain is up to ten serial round-trips, and this runs in
    # request paths ("check my domain" pages) where that is not acceptable
    # twice. Failures (nil) are deliberately NOT cached: caching a timeout would
    # pin a healthy domain into :unknown for the whole TTL.
    class CachingResolver
      def initialize(resolver, ttl: 300, clock: -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) })
        @resolver = resolver
        @ttl = ttl
        @clock = clock
        @entries = {}
        @mutex = Mutex.new
      end

      def call(name)
        key = Record.normalize_name(name)
        now = @clock.call
        cached = @mutex.synchronize { @entries[key] }
        return cached[1] if cached && cached[0] > now

        answer = @resolver.call(key)
        @mutex.synchronize { @entries[key] = [now + @ttl, answer] } unless answer.nil?
        answer
      end

      def clear
        @mutex.synchronize { @entries.clear }
      end
    end
  end
end
