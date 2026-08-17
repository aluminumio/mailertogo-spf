# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-08-17

Answers a second question about a record: not only "does it authorize me, and
what did that cost", but "what does it cost a receiver that has to evaluate all
of it" — the number every other SPF checker reports, and the one a domain owner
compares against.

### Added

- `MailerToGo::SPF.chain_audit` / `MailerToGo::SPF::ChainAudit` — prices a whole
  record tree against the RFC 7208 §4.6.4 budget, term by term, with a running
  total. Deliberately a different number from `Result#lookups`, which stops
  where the receiver stops (§4.6.2): a record can authorize you at a cost of 10
  while costing 11 overall and being broken for everyone listed after you.
  Reports `over_limit?`, `headroom`, `partial?` (part of the chain did not
  resolve, so the total is a floor) and `capped?` (past `CEILING`, where the
  exact number stops changing what anyone should do), and names the chain
  defects found on the way: `targets_without_spf` (§5.2) and
  `duplicated_in_chain` (§4.5). Pass `record:` to price a record that is not
  published yet, or omit it to have the apex resolved.
- `MailerToGo::SPF::Term` — one term of a record as an immutable object that
  answers questions (`include?`, `querying?`, `unreachable?`, `unknown?`,
  `qualifier_meaning`, `all_suffix`, `kind`) instead of being re-matched at
  every call site. Subclassable, and built through `term_class:` on both
  `Record.parse_terms` and `ChainAudit`, so a consumer can hang its own
  human-facing copy off a term without standing up a second parser behind it.
- `Record.parse_terms(record, term_class:)` — a record's terms as `Term`s,
  numbered from 1 in record order. `Record.terms` still returns strings.
- `MailerToGo::SPF.normalize_hostname` / `.hostname?` (and
  `MailerToGo::SPF::Hostname`) — the gate for untrusted input in front of
  anything that resolves DNS on request. Forgiving about shape (a pasted URL,
  an email address, a trailing dot), strict about the result: a syntactically
  valid hostname, or nil. Distinct from `Record.normalize_name`, which
  normalizes a name that came out of a record and never rejects.

### Changed

- The qualifier map, the querying-mechanism list, the modifier regex and the
  `all`-with-junk regex are now defined once, on `Term`, and read from there by
  `Authorization` and `MergePlan`. `Authorization::QUERYING_MECHANISMS` and
  `ALL_QUALIFIERS` keep their names and values.
- `MergePlan::ALL_TERM` and `MergePlan::MODIFIER_TERM` are removed; `MergePlan`
  asks `Term` what a term is. Behaviour of the merge is unchanged.

## [0.1.0] - 2026-08-16

First release. Extracted from the SPF engine MailerToGo runs behind its own
domain setup and monitoring.

### Added

- `MailerToGo::SPF.authorize` — resolves a domain's SPF the way a receiving MTA
  does: follows `include:` and the `redirect=` modifier, stops at the first
  matching mechanism (RFC 7208 §4.6.2), and counts DNS-querying terms against
  the §4.6.4 cap of 10. Returns a five-valued `Result`
  (`:pass` / `:pinned` / `:fail` / `:permerror` / `:unknown`) with predicates,
  the matched name, the lookups a receiver spends, and the terminal `all`
  qualifier (§5.1) as a separate field.
- `:pinned` — its own status for a record that hardcodes the sender's addresses
  instead of including it: passes SPF today, breaks silently the day an address
  moves.
- `MailerToGo::SPF.merge_plan` — given what is already published at a name,
  returns a `Plan` (`:publish` / `:merge` / `:deduplicate` / `:satisfied`) and a
  single merged record that preserves the domain's own `all` qualifier, puts the
  new include last, drops terms glued onto or stranded after `all` (with notes),
  and is **withheld** when merging would push the record past the lookup cap.
- Injectable DNS: any object responding to `#call(name)`, with a stdlib
  `Resolv::DNS` default and an optional `CachingResolver`. No runtime
  dependencies, no Rails.

[0.2.0]: https://github.com/aluminumio/mailertogo-spf/releases/tag/v0.2.0
[0.1.0]: https://github.com/aluminumio/mailertogo-spf/releases/tag/v0.1.0
