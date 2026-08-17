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

It answers three questions about a name: does its SPF **authorize** you, what
should it **publish** given what is already there, and what does the record
**cost** a receiver that evaluates all of it.

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

## What does this record cost?

`authorize` counts the lookups spent up to the point where **you** match,
because §4.6.2 ends a receiver's evaluation at the first matching mechanism.
That is the right number for a gating decision and the wrong number for a page
about the record itself, where the question is what the record costs a receiver
that has to evaluate *all* of it — the number every other SPF checker reports.

`chain_audit` walks the whole tree and prices it against the §4.6.4 budget of
ten, attaching each cost to the term that incurred it:

```ruby
audit = MailerToGo::SPF.chain_audit("example.com")

audit.total       # => 3
audit.limit       # => 10
audit.headroom    # => 7    — lookups still available before the cap
audit.over_limit? # => false

audit.terms.map { |t| [t.raw, t.lookups, t.running_total] }
# => [["include:_spf.google.com", 3, 3],   # itself, plus the two includes inside it
#     ["ip4:198.51.100.7",        0, 3],   # already an address; no DNS
#     ["~all",                    0, 3]]
```

An `include:` costs one lookup **plus everything the record it pulls in costs**,
which is why a record with three terms can be most of the way through the
budget. That is the arithmetic people get wrong by hand, and the reason a
domain that has added one provider too many cannot see it in the record.

The two numbers can disagree about the same record, and both are right:

```ruby
# v=spf1 include:p1… ×8  include:relay.example.net  include:_spf.mailertogo.net ~all

MailerToGo::SPF.authorize("example.com").lookups   # => 10 — a receiver matches you and stops
MailerToGo::SPF.chain_audit("example.com").total   # => 11 — evaluating all of it costs 11
```

Your mail passes at every receiver today. The record is still over the cap, so
everything listed *after* your include has already stopped passing, and the
first person to add a provider breaks yours too. Report only the first number
and you tell that domain owner their record is fine.

The audit also names the defects it finds on the way down, each of which
permerrors the whole evaluation rather than quietly doing nothing:

```ruby
audit.targets_without_spf  # => ["nothing.example.net"]  — include: of a name with no SPF (§5.2)
audit.duplicated_in_chain  # => ["two.example.net"]      — two v=spf1 records in the chain (§4.5)
audit.apex_duplicated?     # => false                    — two at the hostname itself (§4.5)
```

`apex_duplicated?` is deliberately separate from `duplicated_in_chain`: the
hostname is not *in* the chain, it is the record being priced. It answers `nil`
— "cannot say" — when you supplied the `record:` yourself, because then we never
looked at the apex. A caller that resolved the apex already knows, and should
report from what it saw rather than ask twice.

A record that does not exist cannot be priced, so `total` and `headroom` are
`nil` rather than `0`. Check `published?` first:

```ruby
audit = MailerToGo::SPF.chain_audit("no-spf.example.com")
audit.published?  # => false
audit.total       # => nil   — not 0; `v=spf1 -all` legitimately costs 0
```

Two honesty flags, because a count you could not finish must never read as "it
fits": `partial?` (part of the chain did not resolve) and `capped?` (the record
is so far past the cap that we stopped resolving — 20 lookups and 200 are the
same record to a receiver). Either one makes `total` a floor, and `headroom`
returns `nil` rather than a reassuring number.

Pass `record:` to price a line that is not published yet, and omit it to have
the apex resolved for you:

```ruby
MailerToGo::SPF.chain_audit("example.com", record: "v=spf1 include:a.example.net include:b.example.net -all")
```

### Terms

A `Term` is one term of a record, asked questions instead of pattern-matched:

```ruby
terms = MailerToGo::SPF::Record.parse_terms("v=spf1 include:_spf.mailertogo.net ~all;google-site-verification=abc")

terms.first.mechanism          # => "include"
terms.first.target             # => "_spf.mailertogo.net"
terms.first.querying?          # => true — it spends from the §4.6.4 budget

terms.last.all?                # => true — still a terminal `all`, junk and all
terms.last.qualifier_meaning   # => :softfail
terms.last.all_suffix          # => ";google-site-verification=abc"
```

That last one is the case worth having: records ending
`~all;google-site-verification=…` are real and not rare, and reading the whole
token as junk loses the record's `all` — and with it the domain's entire policy
for unauthorized mail.

There is deliberately **no English sentence** on a term. A description of what a
term means is product voice; it belongs to whoever is writing to their own
customers, in their own words. What the gem gives you instead is somewhere to
put it — subclass `Term`, and both `Record.parse_terms` and `ChainAudit` will
build and price yours:

```ruby
class AnnotatedTerm < MailerToGo::SPF::Term
  def meaning
    return "Everything else is marked, not rejected." if all? && qualifier == "~"
    return "Applies #{target}'s own SPF record here." if include?

    …
  end
end

MailerToGo::SPF.chain_audit("example.com", term_class: AnnotatedTerm).terms.map(&:meaning)
```

## Untrusted input

If the hostname came from a form, an API parameter or an uploaded file rather
than from your own database, check it before you resolve anything: an SPF walk
is recursive DNS performed on request.

```ruby
MailerToGo::SPF.normalize_hostname("https://WWW.Example.com/pricing?x=1")  # => "www.example.com"
MailerToGo::SPF.normalize_hostname("billing@example.com")                  # => "example.com"
MailerToGo::SPF.normalize_hostname("example.com:5353")                     # => "example.com"
MailerToGo::SPF.normalize_hostname("v=spf1")                               # => nil
MailerToGo::SPF.hostname?("192.0.2.1")                                     # => false
```

Forgiving about shape — people paste URLs and email addresses into a box
labelled "domain" and are not wrong to expect that to work — and strict about
the result: a syntactically valid hostname, or `nil`. A scheme, a port, a path,
a query string or an address literal is stripped or refused before any resolver
sees it, and there is no way to name a resolver or a port through it.

It is a separate call rather than something folded into `authorize`, on purpose.
"That is not a hostname" is a fact about your **input**; the statuses on
`Result` are facts about somebody's **DNS**, and conflating the two would mean
inventing a sixth status for a mistake DNS had nothing to do with. It is also
not `Record.normalize_name`, which lowercases a name that came out of a record
and never rejects.

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

The gem's own suite is built that way: 137 examples, zero network access.

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
