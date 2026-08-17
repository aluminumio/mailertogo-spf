# frozen_string_literal: true

module MailerToGo
  module SPF
    # Is this untrusted input a name we are willing to resolve?
    #
    # Everything else in this gem takes a hostname it trusts. This is the gate
    # for the case where it did not come from your own database — a box on a
    # page labelled "domain", an API parameter, a CSV somebody uploaded. Asking
    # a resolver to walk an SPF chain is recursive DNS performed on request, so
    # what gets handed to it should be a plausible DNS name and nothing else:
    # anything that could steer the lookup somewhere unintended — a scheme, a
    # port, a path, a query string, an address literal — is stripped or refused
    # here, before any resolver sees it.
    #
    # It is forgiving about SHAPE, because people paste
    # "https://www.example.com/pricing" or "billing@example.com" into a box
    # labelled "domain" and are not wrong to expect that to work, and strict
    # about the RESULT: a syntactically valid hostname, or nil.
    #
    # Distinct from Record.normalize_name, and deliberately so. That one
    # lowercases a name that came out of an SPF record and drops its root dot;
    # it never rejects, because a name inside a record is already as trusted as
    # the record. This one is a gate, and its job is to say no.
    module Hostname
      module_function

      # RFC 1035 §2.3.4 — 253 octets of presentation form, 63 per label.
      MAX_LENGTH = 253

      # A DNS label. Underscores are allowed because SPF names are real targets
      # people check — `_spf.google.com` and `_spf.mailertogo.net` are the two
      # most likely things anyone types into such a box after their own domain.
      LABEL = /\A[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\z/

      # An address literal is not a name to resolve SPF at.
      IPV4 = /\A\d{1,3}(\.\d{1,3}){3}\z/

      # A TLD is alphabetic, so "1.2" and "v=spf1" never reach a resolver.
      TLD = /\A[a-z]{2,}\z/

      # The hostname to resolve, or nil when the input is not one.
      def parse(input)
        host = input.to_s.strip.downcase
        return nil if host.empty?

        host = host.sub(%r{\A[a-z][a-z0-9+.-]*://}, "")   # a pasted URL
        host = host.split("@").last.to_s                  # an email address
        host = host[%r{\A[^/?#]*}].to_s                   # path, query, fragment
        host = host.split(":").first.to_s                 # never honour a supplied port
        host = host.delete_prefix("[").delete_suffix("]") # an IPv6 literal in URL form
        host = host.chomp(".")                            # the root dot is optional

        return nil if host.empty? || host.length > MAX_LENGTH
        return nil if host.match?(IPV4)

        # No IDN here: resolvers speak ASCII, and guessing at an encoding for
        # somebody's DNS name is worse than telling them to paste the A-label.
        labels = host.split(".", -1)
        return nil if labels.size < 2
        return nil unless labels.all? { |label| label.match?(LABEL) }
        return nil unless labels.last.match?(TLD)

        host
      end

      def valid?(input)
        !parse(input).nil?
      end
    end
  end
end
