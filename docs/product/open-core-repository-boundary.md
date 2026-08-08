# Open-Core Repository Boundary

**Status:** Accepted direction  
**Decision date:** 2026-08-08  
**Owner:** Adam Gell

## Decision

Adopt a traditional open-core product model with this controlling repository boundary:

### Public open-source upstream

`adamgell/cmtraceopen` remains public and MIT licensed.

It continues as a genuinely useful local endpoint investigation product and the upstream source for broadly applicable improvements such as:

- local log viewing and tailing;
- parsers, normalization, reducers, findings, and redaction;
- local Intune, Autopilot, ESP, application, identity, SCCM, event-log, and other diagnostic workspaces;
- manual evidence-bundle analysis;
- local timelines and exports;
- general performance, accessibility, correctness, dependency, and security improvements.

The commercial downstream may selectively accept improvements from this repository through reviewed upstream-intake pull requests.

### Private commercial platform

`adamgell/cmtraceopen-web` is not intended to remain an open or community-contribution surface.

Its agent, API server, web console, infrastructure, deployment tooling, operational corpus, and future lifecycle-platform development form commercial platform IP and should move into, or be continued within, a private company-owned repository.

The private platform includes or will include:

- endpoint-agent enrollment and lifecycle;
- remote evidence ingestion, query, and retrieval;
- device/asset continuity across wipes and repairs;
- hardware incarnations, OS instances, registrations, and management aliases;
- collection jobs and event-triggered evidence;
- organization authentication, RBAC, audit, and retention;
- enterprise deployment, updates, compatibility, and support tooling;
- fleet history, clustering, and intelligence;
- commercial web administration and operations;
- future guarded endpoint actions.

There is no expectation that commercial platform work will be contributed back to a public `cmtraceopen-web` upstream.

## Product relationship

```text
Public CMTrace Open
local investigation engine
          │
          │ selected, reviewed upstream improvements
          ▼
Private commercial desktop
renamed downstream investigation cockpit
          │
          │ commercial protocol and product integration
          ▼
Private commercial platform
agent · server · web · identity · jobs · fleet operations
```

The commercial desktop should also be an independent, renamed, private downstream initialized from CMTrace Open history. It may continue accepting selected CMTrace Open improvements.

The private platform is different: it is not maintained as a bidirectional open-source relationship and does not owe feature contributions to a public platform upstream.

## Contribution-flow policy

### CMTrace Open → commercial desktop

Expected and encouraged through reviewed intake:

- parser fixes;
- new local analyzers and workspaces;
- evidence-model correctness;
- UI, accessibility, and performance improvements;
- dependency and security updates;
- general local-product improvements.

### Commercial desktop → CMTrace Open

Optional, not obligatory.

A generally useful local investigation fix may be contributed upstream when doing so benefits CMTrace Open and reduces downstream divergence. Commercial product work is not automatically upstreamed.

### Commercial platform → public repositories

No default contribution-back policy.

Agent, server, fleet, identity, job, organization, lifecycle, enterprise web, deployment, operations, and commercial integration work remain private unless Adam makes a specific later decision to publish an isolated component, protocol, verifier, or security fix.

## Public specifications that may still be valuable

Keeping the implementation private does not require every contract to be secret. The product may publish selected specifications or verification tools when that increases customer trust or interoperability, for example:

- evidence-bundle manifest schema;
- bundle/file hash rules;
- signature verification rules;
- export schema;
- protocol capability identifiers;
- a read-only evidence verifier.

Publishing a specification does not imply publishing the commercial platform implementation.

## Transition for the existing public `cmtraceopen-web`

Because code already released publicly remains available under its existing license, making the repository private does not revoke prior public copies or licenses.

The transition plan should therefore be:

1. Record the final public commit and release/tag state.
2. Preserve all existing license and attribution obligations in the private continuation.
3. Create an independent company-owned private repository retaining Git history.
4. Move active agent/server/web/platform development to the private repository.
5. Redirect submodules, CI, GHCR, signing, update, deployment, and documentation references to company-owned resources.
6. Decide whether the former public repository is archived, made private where GitHub permits, or retained as a historical read-only snapshot.
7. Do not promise ongoing public feature development or contribution acceptance for the platform.
8. Handle critical vulnerabilities in already distributed public artifacts case by case, without creating an open contribution obligation.

## Commercial boundary

The customer is not paying for hidden log parsers. The customer pays for the managed lifecycle system around the investigation engine:

- remote evidence appearing in the desktop investigation experience;
- an agent present from early provisioning through retirement;
- trustworthy asset continuity;
- evidence provenance and chain of custody;
- reliable collection, transport, storage, and retrieval;
- organizational controls and fleet operations;
- supported releases, deployment, upgrades, and operations.

## Superseding clarification

Where earlier product discussion suggested that `cmtraceopen-web` might remain a public reference implementation, public core platform, or bidirectional upstream, this decision supersedes that suggestion.

**The controlling direction is:**

> CMTrace Open remains public. The agent/server/web platform becomes private commercial product IP. The commercial desktop selectively consumes CMTrace Open improvements; the private platform has no default contribution-back relationship.
