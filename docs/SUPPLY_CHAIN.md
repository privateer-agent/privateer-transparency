# Supply chain — how you know the code you install is the code we published

This repo lets you audit Privateer's *privacy* claim. This document covers the
adjacent claim that makes auditing worth anything: that the packages and
binaries you actually install are built from the code you can read, and that
our own build isn't a vector into your machine. npm supply-chain attacks are
real and recurring (`event-stream`, `ua-parser-js`, `node-ipc`, a steady
stream of typosquats and account takeovers) — "trust us, it's fine" is not an
answer, so here is what we do and, more importantly, **how you check it
yourself**.

## The two directions of the problem

1. **You install our package.** How do you know `privateer-agent` on npm is
   built from the public repo, and doesn't run anything on your machine at
   install time?
2. **We install our dependencies.** How do you know the code we ship wasn't
   compromised by one of the ~hundreds of transitive packages *we* depend on?

## Direction 1: installing Privateer is verifiable and inert

### No install scripts — by design, and checkable

`privateer-agent` ships **zero** `preinstall`/`install`/`postinstall` scripts.
Nothing executes on your machine when you install it; dependency patches are
applied at *launch*, inside the code you can read. Check it yourself:

```sh
npm view privateer-agent scripts   # no install/postinstall hooks
npm i -g --ignore-scripts privateer-agent   # installs and runs fine like this
```

We recommend `ignore-scripts=true` in your own `~/.npmrc` generally — our
package is built to work under it, and most npm malware dies with that one
line.

### Provenance: the tarball is bound to the public repo

Every release is published from GitHub Actions with **npm provenance**
(trusted publishing): a signed Sigstore attestation binds the exact tarball on
npm to a public repo, commit, and workflow run. There is **no npm publish
token in existence** — a per-run OIDC credential is minted by the registry, so
a stolen maintainer laptop can't publish anything. Check it yourself:

```sh
npm audit signatures            # in a project that depends on privateer-agent
```

or open the package page — npmjs.com/package/privateer-agent — and follow the
"Built and signed on GitHub Actions" provenance badge back to the actual build
log and commit.

### Bundles: the primary install path skips npm entirely

The `privateer.pro` installers download a **self-contained per-platform
bundle** from a GitHub release: a pinned Node runtime plus an
already-resolved, CI-smoke-tested dependency tree. You never run dependency
resolution, never execute an install script, and get the same bytes CI booted
before publishing. For the strongest posture, use the bundle.

## Direction 2: how we keep our own dependencies from compromising the build

These controls live in the (public) `privateer-agent` repo — `.npmrc`,
`.github/dependabot.yml`, `.github/workflows/release.yml` — where you can read
them; the same policy is applied across the closed server codebase mirrored
here.

- **`ignore-scripts=true` everywhere it can hold.** No dependency executes
  code at install time, on laptops or in CI. Every dep that declares a hook
  was verified to work without it (prebuilt binaries shipped in-package or via
  optional platform deps). The two documented exceptions — the mobile client
  (React Native's `patch-package` step) and the desktop shell (Electron's
  binary download) — carry explanatory `.npmrc` files, and a *new* dep adding
  an install script there is treated as a review flag.
- **Exact pins + lockfile installs.** `save-exact=true`; CI and production
  build with `npm ci` against a committed lockfile with per-package integrity
  hashes. Version movement is a deliberate, human-reviewed diff — never
  semver drift at install time.
- **Upgrade cooldown.** Dependency updates wait a minimum of 7 days after a
  release (14 for majors) before being proposed. Nearly every npm malware
  incident is caught and unpublished within days — we let the ecosystem
  absorb the hit before we upgrade.
- **Signature audit before publish.** The release workflow runs
  `npm audit signatures` over the entire installed tree — registry signatures
  and provenance attestations — before anything is built and published from
  it, so a registry-side tarball swap fails the release instead of shipping.
- **Tag/version binding.** The release workflow refuses to publish when the
  git tag doesn't equal the package version, so a mistagged push can't put
  unreviewed code under a reviewed tag's provenance.

## What's verifiable vs. what's asserted

In the spirit of this repo: be precise about which claims you can check.

| Claim | Status |
|---|---|
| `privateer-agent` has no install scripts | **Verifiable** — `npm view privateer-agent scripts` |
| npm tarball built from the public repo by CI | **Verifiable** — provenance attestation on the package page / `npm audit signatures` |
| No long-lived npm token exists | **Verifiable in effect** — the public workflow has no token secret, and npm's trusted-publisher config only accepts that workflow |
| Bundles match CI output | **Verifiable** — GitHub release assets are produced by the public workflow run |
| Server/client dep policy (`ignore-scripts`, pins, cooldown) | **Asserted** — the monorepo is closed; the policy is stated here and its public half is in the `privateer-agent` repo |
| Dependencies are benign at runtime | **Not provable by anyone** — pins, cooldown and a small dep surface reduce the risk; provenance tells you *where* code came from, not that it's safe |

## What this does not solve

`ignore-scripts` stops install-time execution, not a dependency that's
malicious when `require`d. Pinning stops silent drift, not a bad version you
deliberately upgrade to. Provenance converts "trust the publisher's laptop"
into "audit the public repo" — which is exactly the trade this repo exists to
offer, but someone still has to read the code. Runtime capability confinement
(LavaMoat-style per-package permissions) is the known next rung on this
ladder if the threat model warrants its cost.
