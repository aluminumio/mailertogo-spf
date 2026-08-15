# frozen_string_literal: true

require "ipaddr"

module MailerToGo
  module SPF
    # Reading and normalising the raw text of an SPF record. Everything here is
    # pure: no DNS, no state, no opinions about who you are.
    module Record
      module_function

      # A hostname as SPF compares them: case-insensitive, root dot optional
      # (RFC 7208 §4.3 — the domain-spec is a DNS name, and DNS names are
      # compared case-insensitively).
      def normalize_name(name)
        name.to_s.strip.downcase.chomp(".")
      end

      # A TXT answer as a single string.
      #
      # A TXT record is a sequence of character-strings, each capped at 255
      # octets (RFC 1035 §3.3.14), so a long SPF record arrives as adjacent
      # quoted chunks — `"v=spf1 include:_spf.mailer" "togo.net ~all"`. RFC 7208
      # §3.3 says to concatenate them with no separator. SPF terms never contain
      # a quote, so joining on quote boundaries is safe.
      def normalize_txt(txt)
        txt.to_s.strip.gsub(/"\s*"/, "").delete('"').strip
      end

      # Is this TXT string an SPF record? RFC 7208 §4.5: the version section is
      # exactly "v=spf1", matched case-insensitively, followed by a space or the
      # end of the record. A TXT record starting "v=spf10" is not SPF.
      def spf_record?(txt)
        txt.to_s.match?(/\Av=spf1(\s|\z)/i)
      end

      # The name an SPF record's `include:` mechanism points at
      # ("v=spf1 include:X ~all" → "X"), so a caller can pass the record it wants
      # published and let us derive the mechanism from it. nil when the record
      # has no include.
      def include_target(record)
        term = record.to_s.split(/\s+/).find { |t| t.downcase.start_with?("include:") }
        term&.split(":", 2)&.last
      end

      # The ip4:/ip6: terms of a term list, as IPAddr networks. Unparseable
      # literals are dropped rather than raised on: a customer's malformed term
      # is their record's problem, not a reason for us to blow up.
      def ip_nets(terms)
        terms.filter_map do |term|
          t = strip_qualifier(term)
          next unless t.downcase.start_with?("ip4:", "ip6:")

          begin
            IPAddr.new(t.split(":", 2).last)
          rescue StandardError
            nil
          end
        end
      end

      # RFC 7208 §4.6.2 — a mechanism may carry a leading qualifier
      # (+ - ~ ?); "+" is the default when it is absent.
      def strip_qualifier(term)
        term.to_s.sub(/\A[+\-~?]/, "")
      end

      def qualifier_of(term)
        term.to_s[/\A[+\-~?]/]
      end

      # The mechanism name of a term ("include:x" → "include", "ip4:1.2.3.4" →
      # "ip4", "a/24" → "a"), or nil when the term is a modifier or junk.
      def mechanism_of(term)
        strip_qualifier(term)[%r{\A([a-z0-9]+)(?::|/|\z)}i, 1]&.downcase
      end

      # The terms of a record, without the leading "v=spf1".
      def terms(record)
        record.to_s.split(/\s+/).drop(1)
      end
    end
  end
end
