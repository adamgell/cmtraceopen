# Commercial Product Naming Brief

**Status:** Exploration — no public name selected  
**Started:** 2026-08-08  
**Owner:** Adam Gell

## Naming layers

Four different names may coexist and should not be confused:

1. **Company / GitHub organization name** — owns private repositories, contracts, domains, and eventually signing identities.
2. **Public product brand** — the customer-facing name for the endpoint evidence and investigation platform.
3. **Internal codename** — a temporary engineering and planning label that can be replaced without customer migration.
4. **Binary publisher identity** — initially `Adam Gell`, regardless of the product brand or repository organization.

A codeword can be selected now without prematurely committing the company or public product brand.

---

# Recommended internal codename

## Project Theseus

**Recommendation:** Use **Project Theseus** as the initial internal codename for the commercial program.

### Why it fits

The Ship of Theseus asks whether an object remains the same object as its components are replaced over time. That is the central identity problem the product must solve:

- a device is wiped and receives a new OS identity;
- Entra and Intune objects are deleted and recreated;
- the agent receives a new registration and certificate;
- disks, network adapters, TPMs, or motherboards are replaced;
- the organization still considers the machine one continuing asset;
- the evidence system must preserve what changed without falsely claiming that every technical identity remained the same.

The product's Asset → Hardware Incarnation → OS Instance → Agent Registration model is a direct practical answer to the Ship of Theseus problem.

### Product-family test

The codename works cleanly in private engineering language:

```text
Project Theseus
Theseus Desktop
Theseus Agent
Theseus Platform
Theseus Console
Theseus Evidence Bundle
Theseus Asset Continuity
```

### Important limitation

`Theseus` is recommended only as an internal codename. It already appears in active technology programs and products, so it should not be assumed to be available as a public trademark or customer-facing brand.

Avoid embedding `theseus` into identifiers that are expensive to migrate, such as:

- permanent application bundle IDs;
- MSI upgrade identities;
- evidence-protocol namespaces;
- certificate subjects;
- customer tenant IDs;
- public domains;
- database identity semantics.

It is acceptable in temporary private repository names, project boards, milestones, and engineering documents if migration is planned.

---

# Naming strategy for the public product

## Meaning pillars

The eventual name should evoke at least two of these concepts:

- evidence;
- continuity;
- endpoint history;
- investigation;
- provenance;
- trust;
- lifecycle;
- a durable record;
- a thread connecting multiple device incarnations.

## Tone

The product should sound:

- serious and enterprise-ready;
- technically credible;
- calm rather than militaristic;
- useful to endpoint engineers, not only security investigators;
- capable of expanding beyond Microsoft Intune without sounding generic;
- appropriate for an agent installed from provisioning through retirement.

## Avoid

Avoid public names that:

- contain `CMTrace`, `Intune`, `Entra`, or another Microsoft mark;
- make the product sound like a generic log viewer;
- imply employee surveillance;
- imply an EDR, SIEM, RMM, or remote-control product;
- overuse `forensics`, `spy`, `watch`, or `recorder`;
- are hard to spell after hearing them once;
- are tied only to Windows;
- cannot support a product family.

## Product-family test

Every finalist should work naturally in all of these forms:

```text
<Name> Desktop
<Name> Agent
<Name> Server or Platform
<Name> Console
<Name> Evidence Bundle
<Name> Investigation
```

It should also sound credible in these sentences:

> The <Name> Agent has been installed since the device was provisioned.

> Open the latest endpoint investigation in <Name> Desktop.

> <Name> preserved the device history across the wipe and motherboard replacement.

---

# Initial public-name explorations

These are conversation starters, not cleared names.

## 1. EpochKeep

### Idea

Preserve the endpoint record across distinct hardware and operating-system epochs.

### Strengths

- directly supports the incarnation/epoch model;
- communicates persistence without using `log`;
- works reasonably well as `EpochKeep Agent`, `EpochKeep Desktop`, and `EpochKeep Platform`;
- memorable and easy to spell;
- preliminary web searching did not reveal an obvious exact active endpoint-software brand.

### Risks

- `keep` may overemphasize storage rather than investigation;
- `epoch` can sound abstract or be associated with time systems and cryptocurrency;
- domain and trademark availability have not been confirmed.

### Working tagline

> Every endpoint epoch, one trusted history.

## 2. TrueEpoch

### Idea

A trustworthy record of each stage in a device's managed life.

### Strengths

- short and pronounceable;
- evokes truth plus lifecycle eras;
- product-family forms are usable.

### Risks

- sounds more abstract than endpoint-specific;
- may suggest time synchronization, blockchain, or cryptocurrency;
- requires complete trademark and domain screening.

## 3. RecordSpan

### Idea

The product preserves the full span of a machine's managed record.

### Strengths

- directly communicates a durable record over time;
- works with desktop, agent, platform, and bundle suffixes;
- preliminary searching did not reveal an obvious exact commercial endpoint product.

### Risks

- `span` is heavily used in distributed tracing and observability terminology;
- could be misunderstood as an OpenTelemetry product;
- less emotionally distinctive.

## 4. ProvenThread

### Idea

One explainable, defensible thread of evidence through the entire endpoint lifecycle.

### Strengths

- closely matches the product thesis;
- `thread` expresses continuity without pretending every identifier remained unchanged;
- strong investigation and provenance meaning.

### Risks

- `proventhread.com` is already occupied by a launching-soon site;
- the name therefore begins with a domain and potential mark obstacle;
- `proven` can sound like an unsupported marketing claim.

**Current disposition:** Conceptually strong, but deprioritized unless ownership and trademark investigation changes the picture.

## 5. Veristory

### Idea

Verifiable history.

### Strengths

- concise expression of the core value;
- easy product story: every endpoint has a verifiable history.

### Risks

- existing uses already appear in data storytelling, media, and other business contexts;
- potential confusion between `Veristory`, `VeriStory`, and `Very Story`;
- spelling may require explanation.

**Current disposition:** Deprioritized.

---

# Names screened out in the first pass

The following had obvious active technology, software, evidence, or adjacent-brand collisions during preliminary searching and should not lead the next round:

- TraceKeep;
- Threadmark;
- TraceFrame;
- ProvenArc;
- ProofArc;
- TraceArc;
- EpochArc;
- Tracehold;
- AssetThread;
- CaseThread;
- ProofKeep;
- Evidentry;
- Continuant;
- Ariadne as a public product brand;
- Theseus as a public product brand.

This is not legal clearance. It is only an early elimination pass intended to avoid spending design energy on obviously crowded names.

---

# Candidate messaging independent of the final name

These lines express the desired category and can be tested before the brand is selected:

> Every endpoint has a history.

> Remote endpoint evidence, inside the investigation experience.

> From first enrollment to final retirement.

> One device history across wipes, repairs, and reenrollment.

> The evidence layer for managed endpoints.

> Retrieve the evidence. Preserve the history. Investigate the device.

> The endpoint flight recorder and investigation cockpit.

The strongest current category statement remains:

> **Endpoint evidence and investigation platform.**

---

# Current recommendation

Use this working structure while public naming continues:

```text
Program codename: Project Theseus
Binary publisher: Adam Gell
Public product:   To be selected
Company/org:      To be selected
```

Use `Project Theseus` in planning and private engineering conversation, but do not yet create customer-facing assets, permanent application identifiers, or public domains under that name.

The next naming round should:

1. gather Adam's positive and negative reactions to the first candidates;
2. generate names in the strongest preferred semantic lane;
3. reduce to five candidates;
4. perform current company, product, GitHub, package, domain, and preliminary USPTO screening;
5. test pronunciation and product-family usage;
6. engage qualified trademark counsel before public launch or material branding spend.
