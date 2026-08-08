# Commercial Repository and Signing Decision

**Status:** Accepted direction  
**Decision date:** 2026-08-08  
**Owner:** Adam Gell

## Decision

Adopt **Option B** for the commercial product:

- create all new commercial repositories under a dedicated GitHub organization;
- initialize the private commercial desktop from the full `adamgell/cmtraceopen` Git history;
- initialize the private commercial platform from the full `adamgell/cmtraceopen-web` Git history;
- treat the original personal repositories as upstream ancestry or historical source, not the long-term home of commercial product development;
- keep CMTrace Open public while moving active agent/server/web/platform development into organization-owned private repositories.

During the startup phase, released binaries will continue to be code-signed under the verified publisher identity **Adam Gell**.

The repository owner, product brand, and binary signing identity are intentionally separate concepts:

```text
Source ownership      Dedicated GitHub organization
Open-source upstream  Adam Gell / CMTrace Open
Commercial product    Name not yet selected
Initial binary signer Adam Gell
Future binary signer  Company identity when established and validated
```

## Initial repository shape

Names remain placeholders until the product codename or public brand is chosen:

```text
<organization>/<codename>-desktop
  Private commercial downstream of CMTrace Open

<organization>/<codename>-platform
  Private continuation of cmtraceopen-web
  Agent · API server · web console · infrastructure

<organization>/<codename>-release
  Private signing, release manifests, compatibility, packaging, and update coordination

<organization>/<codename>-docs
  Private product, security, customer, architecture, and operations documentation
```

Only the first two repositories are required to begin development. Release and documentation material can remain inside those repositories until separation provides a practical benefit.

## Signing policy during startup

1. Sign every distributed executable, installer, library where appropriate, and release artifact supported by the existing pipeline under **Adam Gell**.
2. Timestamp signatures so already-issued binaries remain verifiable after the signing certificate expires.
3. Keep signing secrets outside source repositories and restrict signing workflows to protected release paths.
4. Treat the signer name shown by the operating system as `Adam Gell`, even when the customer-facing product has a separate brand.
5. Document the relationship in release material when needed:

   > Published and digitally signed by Adam Gell.

6. Do not encode the founder signing identity into product concepts that should survive company formation:
   - logical product ID;
   - database tenant or asset IDs;
   - protocol names;
   - evidence manifest identity;
   - service architecture;
   - update-channel model;
   - customer licensing model.
7. Preserve stable installer and application identity deliberately so a later signer transition does not accidentally create a second installed product.
8. Plan the future move to a company-owned signing identity as a controlled release event with upgrade, reputation, trust, and customer-communication testing.

## Signer migration considerations

A future transition from `Adam Gell` to a verified company publisher will be legitimate, but it should not be assumed to be invisible.

The release plan must account for:

- Windows displaying a different verified publisher;
- SmartScreen and publisher-reputation behavior changing when the publisher identity changes;
- customer allowlists or application-control policies that reference the old signer;
- signing-certificate trust and revocation configuration;
- MSIX manifest publisher matching if MSIX is used;
- update and installer tests from the founder-signed release to the company-signed release;
- documentation for customers using WDAC, AppLocker, Defender for Endpoint, Intune, or other publisher-based controls;
- preserving old timestamped release signatures and their verification chain.

The commercial product must therefore maintain a machine-readable signing history and compatibility record, for example:

```json
{
  "productId": "<stable-product-id>",
  "release": "0.4.0",
  "publisher": "Adam Gell",
  "publisherGeneration": 1,
  "signedAt": "2026-08-08T00:00:00Z"
}
```

A later company signer becomes publisher generation 2 without changing the logical product identity.

## Ownership boundary

Commercial repositories should be organization-owned from their creation so that:

- access can be granted by team and role rather than personal-account sharing;
- Actions secrets, environments, packages, and branch protection belong to the product organization;
- future employees, contractors, or investors can be granted scoped access;
- commercial IP is not operationally tied to one personal repository namespace;
- customer-facing releases can later move to company domains and signing identities without moving source ownership again.

Adam remains the initial owner and release authority, and the founder signing identity remains acceptable for startup and design-partner activity.

## Immediate actions after naming direction

1. Select an internal codename.
2. Select or create the GitHub organization.
3. Create the private desktop and platform repositories.
4. Mirror complete history and tags from their source repositories.
5. Record exact source baselines in `UPSTREAM.md` or equivalent ledgers.
6. Redirect the commercial platform submodule/dependency relationship to the private commercial desktop.
7. Establish founder-signed preview release channels.
8. Keep application identifiers and installer upgrade identities stable and independent from the eventual company signer.
