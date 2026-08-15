# frozen_string_literal: true

require "mailertogo/spf/record"

module MailerToGo
  module SPF
    # The sender you are asking about: "which names in a customer's SPF record
    # mean *me*?"
    #
    # It is deliberately a set, not a single string. A sending service usually
    # publishes a chain — an outer alias that customers are told to include, and
    # a leaf that actually lists the addresses:
    #
    #   mailertogo.net       TXT  v=spf1 include:_spf.mailertogo.net ~all
    #   _spf.mailertogo.net  TXT  v=spf1 ip4:… ip4:… ~all
    #
    # A customer who publishes `include:mailertogo.net` is authorised just as
    # surely as one who publishes `include:_spf.mailertogo.net`; both must count,
    # or you report a false failure against a domain that passes at every real
    # receiver. Staging/regional spellings of the same zone belong here too.
    class Sender
      attr_reader :include_name, :names

      # include_name — the mechanism you tell customers to publish.
      # aliases      — any other name that is equally you (outer alias, staging
      #                zone, a legacy name you still honour).
      def initialize(include_name, aliases: [])
        @include_name = Record.normalize_name(include_name)
        raise ArgumentError, "include name is required" if @include_name.empty?

        @names = ([@include_name] + Array(aliases).map { |n| Record.normalize_name(n) })
                 .reject(&:empty?)
                 .uniq
                 .freeze
        freeze
      end

      # Does this name in someone's record mean us?
      def covers?(name)
        names.include?(Record.normalize_name(name))
      end

      # The standalone record a domain with no SPF of its own should publish.
      def record(all: "~all")
        "v=spf1 include:#{include_name} #{all}"
      end

      def to_s
        include_name
      end
    end
  end
end
