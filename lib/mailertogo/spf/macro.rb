# frozen_string_literal: true

require "ipaddr"

module MailerToGo
  module SPF
    # RFC 7208 §7 macro expansion — the part of it that does not need a message.
    #
    # A receiver expands macros from the SMTP session: the connecting address,
    # the envelope sender, the HELO name. We have no session. But the
    # authorization question is about one thing we DO know — the addresses we
    # send from — so %{i} (and %{v}, which is only that address's family) can
    # be expanded exactly as a receiver would for mail from us. %{d} (the
    # domain whose record is being evaluated) and %{o} (the sender's domain)
    # are known too.
    #
    # Everything else (%{s} %{l} %{h} %{p}) depends on a message we do not
    # have. A string that uses any of them expands to nil — "cannot say" — and
    # the caller treats the term exactly as it did before macros were read.
    module Macro
      # §7.1: %{ letter [digits] [r] [delimiters] }, the three escapes, a
      # literal run, or a bare `%` (a syntax error, so: cannot say).
      TOKEN = %r{%\{(?<letter>[a-z])(?<digits>\d*)(?<reverse>r?)(?<delims>[.\-+,/_=]*)\}|
                 %(?<escape>[%_-])|(?<literal>[^%]+)|%}xi
      ESCAPES = { "%" => "%", "_" => " ", "-" => "%20" }.freeze

      # §7.3: an expanded name longer than this loses labels from the left.
      MAX_NAME = 253

      module_function

      # Does this domain-spec depend on the connecting address? Only such a term
      # says anything about US rather than about every sender at once.
      def per_address?(spec) = spec.to_s.match?(/%\{i/i)

      # spec          — a domain-spec from a record, e.g. "%{ir}.%{v}._spf.example.com"
      # address       — IPAddr: the connecting address %{i} stands for
      # domain        — %{d}, the domain whose record holds the term
      # sender_domain — %{o}, the domain of the envelope sender
      #
      # Returns the expanded name, or nil when the spec uses a macro that needs
      # a message (or is malformed).
      def expand(spec, address:, domain:, sender_domain:)
        values = {
          "i" => dotted(address),
          "v" => address.ipv4? ? "in-addr" : "ip6",
          "d" => domain,
          "o" => sender_domain,
        }
        name = spec.to_s.gsub(TOKEN) do
          m = Regexp.last_match
          next m[:literal] if m[:literal]
          next ESCAPES.fetch(m[:escape]) if m[:escape]

          # An upper-case letter asks for URL escaping (§7.3); every value we
          # can supply is already URL-safe, so case does not matter here.
          value = m[:letter] && values[m[:letter].downcase]
          # §7.1: a DIGIT transformer of zero is invalid.
          return nil if value.nil? || m[:digits] == "0"

          transform(value, m[:digits], m[:reverse], m[:delims])
        end
        name = name.sub(/\A[^.]*\./, "") while name.length > MAX_NAME && name.include?(".")
        name
      end

      # §7.3: split on the delimiters (default "."), reverse if asked, keep the
      # rightmost N parts, rejoin with ".".
      def transform(value, digits, reverse, delims)
        parts = value.split(Regexp.union((delims.empty? ? "." : delims).chars))
        parts.reverse! unless reverse.empty?
        parts = parts.last(digits.to_i) unless digits.empty?
        parts.join(".")
      end

      # §7.3: IPv4 is dotted-quad; IPv6 is 32 dot-separated nibbles.
      def dotted(address)
        address.ipv4? ? address.to_s : address.to_string.delete(":").chars.join(".")
      end
    end
  end
end
