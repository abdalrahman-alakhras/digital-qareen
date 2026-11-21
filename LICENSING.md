# Digital Qareen DQ-IV01 — Public License Boundary

## Selected distribution model

- **Source-available, noncommercial**; NOT OSI-approved open source.
- Software and machine-readable replay artifacts: **PolyForm Noncommercial
  License 1.0.0** (`LICENSE`), SPDX `PolyForm-Noncommercial-1.0.0`.
- Original explanatory prose and research documentation: **CC BY-NC 4.0**
  (`LICENSE-DOCUMENTATION.md`).
- Copyright notice: `NOTICE` (preserve every line beginning `Required Notice:`
  when distributing software under PolyForm).
- No patent, trademark, logo, or other license beyond the applicable grant
  is implied. PolyForm itself contains a limited express patent grant.

## Precise scope

The intended package is **only** the public DQ-IV01 focused synthetic
supervision replay (baseline public commit
`2f0e8de65a8b94bbc28578879b616e6f662f4a3f`, plus a future
reviewed release commit). The private `zero-data-intent-poc` engineering
repository, unpublished migration files, credentials, deployment artifacts,
and additional code are NOT included.

This proposed release does not license third-party contributions beyond the
rights the licensor actually controls. The presence of an import such as
`asyncpg` or `httpx` does not automatically distribute those dependencies;
their own licenses remain applicable if redistributed independently.

## Allowed uses and restrictions

The full official PolyForm text controls interpretation. It permits
noncommercial purposes, personal research, experiments, and certain use
by educational, public research, charitable, government, and similar
organizations even if they receive funding. It is **not** a blanket ban
on all funded institutional activity.

Any use not covered by the applicable noncommercial license requires a
separate commercial license or other permission from the copyright holder,
unless the use is independently lawful under copyright exceptions.

Attribution must be kept according to the applicable license. The software
license specifically requires preserving the license URL/text and required
notices. No license can fully prevent copying or misuse; enforcement is a
separate issue.

## Research scope and non-claims

The witness compiles and executes selected Python AST definitions with
synthetic dependency substitutes. This is **not** a hostile-code sandbox.
There is no claimed proof of real PostgreSQL behavior, live OS signal
handling, real provider integration, production readiness, or independent
membership of the original private Git history.

An external reviewer reported replaying the public package on Python 3.13;
the author's local replay on Python 3.14.0 was reported. The new release
has NOT yet passed final tests or been published.

## Key verification

The original public commit uses SSH Ed25519 signing key fingerprint:
`SHA256:57SaZ/ggJUT13z8JWoxuFuAKSLv/GNdUYbPmr3vrK7E`

A locally reviewed candidate allowed-signers file is not yet published.
GitHub-account key corroboration does not prove legal identity or the
original private commit history.

## Dual commercial licensing

The author may separately authorize commercial use of **his licensable
contributions** in writing. Such permissions do not grant ownership or
rights in third-party material. No commercial license is granted by this
file, and no fee schedule is implied.
