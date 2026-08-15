# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.0]: https://github.com/aluminumio/mailertogo-spf/releases/tag/v0.1.0
