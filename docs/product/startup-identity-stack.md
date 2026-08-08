# Startup Identity Stack

**Status:** Accepted direction  
**Decision date:** 2026-08-08  
**Owner:** Adam Gell

## Canonical identity stack

```text
Internal program:  Project Theseus
Binary publisher:  Adam Gell
Repository owner:  New organization
Public product:    Still under exploration
```

## Meaning

### Internal program — Project Theseus

`Project Theseus` is the internal codename for product planning, architecture, milestones, and private engineering coordination.

It reflects the product's core asset-continuity problem: preserving one explainable device history while hardware, operating-system, agent, and management identities change over time.

It is not yet approved as the public product brand and should not be embedded in identifiers that are expensive to migrate.

### Binary publisher — Adam Gell

During startup and design-partner activity, distributed binaries and installers will be digitally signed under the verified publisher identity `Adam Gell`.

The signer identity is distinct from the product brand, repository organization, protocol identity, application identity, and future company identity.

### Repository owner — New organization

All new commercial repositories will be created under a dedicated GitHub organization rather than under a personal repository namespace.

The organization name is not yet selected. It will own the private commercial desktop, private platform, release workflows, Actions environments, secrets, packages, and related commercial development assets.

### Public product — Still under exploration

No customer-facing product name has been selected.

Naming exploration should continue without delaying private engineering work. The public brand must remain independent of `CMTrace`, `Intune`, `Entra`, `Project Theseus`, and the founder's binary-signing identity.

## Repository naming until a public brand is selected

Use temporary, replaceable private naming rather than pretending the codename is final. Suitable placeholders include:

```text
<organization>/theseus-desktop
<organization>/theseus-platform
```

Before the first external production release, review and migrate any codename-based repository, package, service, cloud-resource, or update-channel names that would expose or permanently bind the internal codename.

## Program execution documents

The accepted identity stack is implemented through:

- [`project-theseus-program-charter.md`](./project-theseus-program-charter.md)
- [`project-theseus-milestone-roadmap.md`](./project-theseus-milestone-roadmap.md)
- [`project-theseus-repository-skeleton.md`](./project-theseus-repository-skeleton.md)
- [`project-theseus-execution-backlog.md`](./project-theseus-execution-backlog.md)
- [`project-theseus-index.md`](./project-theseus-index.md)

## Controlling rule

> Project Theseus names the internal program. Adam Gell signs the startup binaries. A new organization owns the commercial repositories. The public product name remains an open decision.