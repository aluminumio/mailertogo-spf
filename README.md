# mailertogo-spf

Read a domain's SPF record the way a receiving mail server does, and work out
what it should publish.

SPF looks like a string and is actually a tree. The obvious check —
"does this domain's TXT record contain `include:_spf.mailertogo.net`?" — is
wrong about a large slice of the real internet, in both directions:

```
example.com          TXT  v=spf1 include:spf.hosting.example include:mailertogo.net ~all
mailertogo.net       TXT  v=spf1 include:_spf.mailertogo.net ~all
_spf.mailertogo.net  TXT  v=spf1 ip4:… ip4:… ~all
```

That domain is authorized. Every receiver agrees. A literal token match says it
is not — and if you gate anything on that answer (verification state, drift
alerts, the ability to send) you have just broken a customer who did nothing
wrong.

This gem resolves the chain instead: it follows `include:` and `redirect=`,
stops at the first mechanism that matches (RFC 7208 §4.6.2), and counts
DNS-querying terms against §4.6.4's cap of 10 — the same arithmetic a receiver
does, so a record this gem passes is a record that passes in the wild.

No Rails. No runtime dependencies. DNS goes through an injectable resolver, so
your test suite never touches the network.

## Install

```ruby
gem "mailertogo-spf"
```

```console
$ gem install mailertogo-spf
```

## Is this domain authorized?

```ruby
require "mailertogo/spf"

result = MailerToGo::SPF.authorize("example.com")

result.pass?          # => true
result.matched        # => "mailertogo.net"  (the name in their record that meant us)
result.lookups        # => 3                 (DNS-querying terms a receiver spends)
result.detail         # => "SPF reaches mailertogo.net through its include chain (3 DNS lookups)"
```

Asking about a different sender is one keyword:

```ruby
MailerToGo::SPF.authorize("example.com", include: "spf.example.net")

# …or, if you publish an outer alias as well as a leaf, name both:
MailerToGo::SPF.authorize("example.com",
                          include: "spf.example.net",
                          aliases: ["example.net"])
```

### The five statuses

| `status`     | What happened | Is it a failure? |
|--------------|---------------|------------------|
| `:pass`      | The include is reachable from the record. Durable authorization. | no |
| `:pinned`    | No include chain to you, but the record hardcodes your current sending IPs. | not yet — see below |
| `:fail`      | The chain resolved fine. You are simply not in it. | yes |
| `:permerror` | The record is broken: two `v=spf1` records (§4.5), or past the §4.6.4 lookup cap. Receivers reject it, so nothing passes. | yes |
| `:unknown`   | DNS did not answer. Verdict withheld. | **no** |

`:unknown` is the important one. A resolver timeout must never be reported as
"this domain removed my record" — that is how a monitoring job un-verifies a
hundred healthy domains during someone else's outage. `failed?` is true for
`:fail` and `:permerror` only.

`:pinned` is the other one worth knowing about. A customer who copies your IP
addresses into their record instead of including you authenticates *today* and
breaks silently the day you move an address — and keeps authorizing that
address after you release it to somebody else. It passes SPF, so a naive
checker calls it a pass; it is a defect, so this gem gives it its own status.

```ruby
result.pinned?    # => true
result.reason     # => :pinned_partial   (they cover only some of your ranges)
result.defect     # => :ip_pinned        (:lookup_limit / :duplicate_records for permerrors)
```

### `-all` versus `~all`

The qualifier on the terminal `all` (§5.1) is what receivers do with mail the
record does *not* authorize: `-all` says reject, `~all` says mark. It rides on
the result as a field rather than a status, because it does not change the
yes/no answer — but it changes how urgently you should tell someone, and what
you tell them:

```ruby
result.all_qualifier   # => :fail | :softfail | :neutral | :pass | nil
result.softfail?       # => true when unauthorized under a ~all
```

### Other things on `Result`

```ruby
result.permerror_with_sender_published?  # their record is broken, but your include IS in it —
                                         # a different problem with a different remedy
result.partial?                          # part of the chain didn't resolve, so `lookups` is a floor
```

## What should they publish?

The instruction "add a TXT record: `v=spf1 include:_spf.mailertogo.net ~all`" is
correct only for a domain with no SPF at all. Give it to a domain that already
has SPF — Google Workspace, a registrar default, Microsoft 365, another ESP —
and a conscientious customer will follow it exactly and end up with **two**
`v=spf1` records. RFC 7208 §3.2 forbids that, §4.5 makes it a permerror, and
the result is worse than doing nothing: it breaks SPF for every sender they
had, not just yours.

`merge_plan` resolves what is published and hands back the instruction that is
actually correct for that domain:

```ruby
plan = MailerToGo::SPF.merge_plan("example.com")

plan.action           # => :publish | :merge | :deduplicate | :satisfied
plan.replacement?     # => true — this is a REPLACE, not an ADD
plan.offered_record   # => "v=spf1 include:_spf.google.com include:_spf.mailertogo.net ~all"
plan.severity         # => :info | :warning
plan.notes            # => human-readable notes about anything dropped
```

| `action` | Meaning |
|----------|---------|
| `:publish` | Nothing there: hand them the standalone record. Also the fallback when DNS did not answer. |
| `:merge` | One record exists and does not authorize you: replace it with `offered_record`. |
| `:deduplicate` | Two or more `v=spf1` records are already published: replace them all with one. |
| `:satisfied` | A single record already reaches you. Say nothing; never rewrite a working record. |

The merge is careful about three things, because each is a way to make a
customer's mail worse rather than better:

- **Their `all` qualifier is their policy.** It is carried across verbatim.
  Quietly rewriting `-all` to `~all` would relax how receivers treat *every*
  sender they have.
- **The new include goes last**, immediately before the terminal `all`, because
  a mechanism after `all` is never evaluated (§5.1/§6.1). Terms that were
  already stranded there are dropped, with a note — keeping them would newly
  authorize a sender that receivers ignore today. Modifiers (`redirect=`,
  `exp=`) are position-independent (§4.6.1) and survive.
- **Merging costs a DNS lookup**, and §4.6.4 caps an evaluation at 10. A record
  already near the cap can be pushed over it, and a record over the cap
  permerrors for everyone. The merged line is measured, and **withheld** if it
  would not fit:

```ruby
plan.over_limit?      # => true
plan.lookups          # => 11
plan.lookup_limit     # => 10
plan.offered_record   # => nil — we will not hand over a line we know breaks on arrival
plan.merged_record    # => still computed, if you want to show it as a diagnosis
```

`Plan` is a null-object away from nil checks — `MailerToGo::SPF::Plan.none`
answers every question as "no instruction" — and it can reconcile a row in a
"publish these records" table for you, so the decision to withhold lives in one
place:

```ruby
plan.replaces?(name: "example.com", value: "v=spf1 include:_spf.mailertogo.net ~all")  # => true
plan.value_for(name: "example.com", value: "v=spf1 include:_spf.mailertogo.net ~all")
# => "v=spf1 include:_spf.google.com include:_spf.mailertogo.net ~all"
```

## DNS

A resolver is anything that responds to `#call(name)` and returns:

| Return | Meaning |
|--------|---------|
| `["v=spf1 …"]` | the TXT strings at that name |
| `[]` | the name publishes no TXT (or does not exist): a definitive "nothing here" |
| `nil` | DNS did not answer: **inconclusive**, and the verdict is withheld |

That three-way return is the whole contract, and the `nil` is the load-bearing
part. The default resolver uses Ruby's stdlib `Resolv::DNS`, which is why this
gem has no runtime dependencies:

```ruby
MailerToGo::SPF::Resolver.new(timeout: 3, nameservers: %w[1.1.1.1 8.8.8.8])
```

Resolving a chain is up to ten serial round-trips, which is not something to do
twice in a request path, so there is a TTL cache. Failures are deliberately not
cached — caching a timeout would pin a healthy domain into `:unknown` for the
whole TTL:

```ruby
MailerToGo::SPF.configure do |c|
  c.resolver = MailerToGo::SPF::CachingResolver.new(MailerToGo::SPF::Resolver.new, ttl: 300)
end
```

Bring your own if you already speak DNS-over-HTTPS. A DoH resolver can see the
response code, so it can draw the `[]` / `nil` line exactly where it belongs:

```ruby
require "net/http"
require "json"

DOH = lambda do |name|
  uri = URI("https://dns.google/resolve?name=#{URI.encode_www_form_component(name)}&type=TXT")
  res = Net::HTTP.start(uri.host, uri.port, use_ssl: true, open_timeout: 3, read_timeout: 4) do |http|
    http.request(Net::HTTP::Get.new(uri))
  end
  return nil unless res.code == "200"

  json = JSON.parse(res.body)
  return [] if json["Status"] == 3        # NXDOMAIN is a definitive "no record"
  return nil unless json["Status"].to_i.zero?  # SERVFAIL etc. is inconclusive

  json.fetch("Answer", []).select { |a| a["type"] == 16 }.map { |a| a["data"].to_s }
rescue StandardError
  nil
end

MailerToGo::SPF.authorize("example.com", resolver: DOH)
```

And in tests, a resolver is a hash and a lambda:

```ruby
zone = {
  "example.com" => ["v=spf1 include:_spf.mailertogo.net ~all"],
  "_spf.mailertogo.net" => ["v=spf1 ip4:192.0.2.10 ~all"],
}

MailerToGo::SPF.authorize("example.com", resolver: ->(name) { zone.fetch(name, []) })
```

The gem's own suite is built that way: 95 examples, zero network access.

## Configuration

Every keyword can be set once instead of per call:

```ruby
MailerToGo::SPF.configure do |c|
  c.include  = "_spf.mailertogo.net"   # the mechanism you want authorized
  c.aliases  = ["mailertogo.net"]      # other names that mean the same sender
  c.resolver = MailerToGo::SPF::Resolver.new
  c.logger   = Rails.logger            # optional; only used for swallowed errors
end
```

The defaults are MailerToGo's own names, so `MailerToGo::SPF.authorize(domain)`
answers the MailerToGo question with no configuration at all.

## What it deliberately does not do

- **Evaluate a message.** There is no `<ip>`/`<sender>` pair here and no
  macro expansion (§7): a term containing `%{i}` costs its DNS lookup and is
  then not followed. This answers "is this sender authorized by this domain",
  which is a setup-time and monitoring question, not a per-message one. For
  per-message evaluation you want a full RFC 7208 evaluator.
- **Change DNS.** Everything here reads.
- **Cache by default.** Wrap the resolver if you want that; see above.

## Who made this

[MailerToGo](https://mailertogo.com) is an SMTP delivery service — you point
your app's SMTP settings at it and it handles sending, DKIM signing, and
delivery reporting. This engine is the one that runs behind our own domain
setup and monitoring, extracted because the SPF-shaped problems it solves are
not specific to us: any service that asks customers to add an `include:` has
customers who publish a second record, hardcode IPs, or sail past the ten-lookup
cap.

## Contributing

Bug reports and pull requests are welcome at
<https://github.com/aluminumio/mailertogo-spf>. A record shape from the wild
that this gem gets wrong makes an especially good issue — please include the
records themselves.

```console
$ bundle install
$ bundle exec rspec
$ bundle exec rubocop
```

## Licence

MIT. See [LICENSE](LICENSE).
