# Digital Qareen — DQ-IV01 focused supervision replay

Disclosure-limited research candidate. Not a production release or security certification.

Two five-file source sets reproduce the original L2-C7 and L3-C8 supervision witness. The witness is unchanged. The source sets are subsets, not full commit trees or an executable Git history. The manifest records the author's locally checked original Git commit, blob and SHA-256 identities. A reviewer without access to the original commit trees cannot independently verify original commit membership from this package alone. The original evidence is retained separately.

## Replay

Inspect the code first. In an isolated disposable environment without live credentials or network access, use Python 3.14.0 (the locally verified version). From this directory run:

```sh
python -I -S -B replay.py
```

The harness extracts selected definitions and simulates I/O. It does not start the full application, PostgreSQL or live providers. Python isolation flags are not an OS security sandbox. No third-party dependencies are intended for this focused witness.

Expected: RED reproduces ten failures and four passing controls (wrapper exit 0); GREEN has fourteen passing scenarios; fatal child exit 1; graceful child exit 0. The runner checks individual outcomes, not just exit codes. It writes logs and a result receipt to a new local temporary directory. Review logs before sharing them; they may contain local paths.

The author's local replay passed on Python 3.14.0. Independent replay remains pending. This package covers the focused supervision witness, not the full 67-scenario regression suite, durable cross-worker recovery, or live production validation.
