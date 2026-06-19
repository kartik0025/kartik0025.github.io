---
title: "Fully certified, completely vulnerable: three chinks in the compliance armour"
date: 2026-06-19T09:30:00+05:30
draft: false
tags: ["grc", "compliance", "security-audit", "cloud-security", "supply-chain"]
summary: "Capital One, SolarWinds, and Schrems II were all fully certified when they were completely breached. Three case studies in the gap between passing an audit and actually being secure — and why that gap is structural, not accidental."
ShowToc: true
TocOpen: false
cover:
  image: "covers/chinks-in-the-armour.png"
  alt: "Fully certified, completely vulnerable — three chinks in the compliance armour"
  hiddenInSingle: true
---

There's a difference between *being compliant* and *being secure*, and several of the most expensive breaches of the last decade happened in the gap between the two.

A certificate is a snapshot. It says that on the day the auditor visited, the controls on the checklist were in place. The breach happens on a different day, through something the checklist never had a line for. ISO 27001, SOC 2, PCI-DSS — an organisation can hold all three, frame them in the lobby, and still be wide open, because the audit and the attack are looking at two different things.

One of my Semester-II courses at NFSU — Cyber Security Audit and Compliance — asked for a case study on exactly this. I went looking for organisations that were *fully certified* at the moment they were *completely breached*, to see whether the failures had anything in common. They did. Three breaches, three different structural blind spots in how auditing works. I called them chinks in the armour: small, specific gaps in a suit of plate that looks complete from the outside.

## The illusion of compliance

The pattern underneath all three deserves a name: **audit–security decoupling**. It's what happens when passing the audit becomes the goal instead of a proxy for the goal. Compliance turns performative — the controls exist on paper, the evidence satisfies the assessor, and none of it maps to whether an attacker can actually get in. The framework returns a *false negative*: it certifies security where none exists.

Here are the three gaps, each with the breach that makes it concrete:

| Chink | The gap | Case study |
|---|---|---|
| **Temporal** | Static audit vs. dynamic infrastructure | Capital One (2019) |
| **Perimeter** | Trusted boundary vs. verified boundary | SolarWinds (2020) |
| **Jurisdictional** | Technical control vs. legal requirement | Schrems II (2020) |

## Chink 1 — the temporal gap: Capital One

Capital One held PCI-DSS, SOC 1/2, and aligned to ISO 27001. In March 2019 a former AWS engineer walked out with the personal data of roughly **100 million** people anyway.

The entry point was a misconfigured web application firewall — a reverse proxy sitting in front of a Capital One app on AWS — that was vulnerable to **server-side request forgery (SSRF)**. SSRF means the attacker can make the server issue HTTP requests *on their behalf*, to destinations of the attacker's choosing. And on any EC2 instance there is one destination that matters more than the rest: the **instance metadata service** at `169.254.169.254`, which hands out the temporary IAM credentials of the role attached to that instance.

```text
GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
```

The WAF's role was over-privileged — it could list and read S3 buckets it had no business touching. So the chain was: SSRF on the proxy → forge a request to the metadata service → receive temporary AWS credentials → call `s3:ListBuckets` and `s3:GetObject` → exfiltrate. Three correctly-configured things combining into one catastrophic one.

**Here's the part that matters for auditing:** every individual control in the report was *compliant*. IAM existed. Security groups existed. The WAF existed. What no annual audit could see was that the *combination* — an SSRF-able proxy, plus an over-broad role, plus a metadata service (IMDSv1) that would hand credentials to anyone who could reach it — was exploitable on one particular Tuesday, in an environment that redeployed itself continuously between audits. The relevant ISO 27001 controls (A.8.8, management of technical vulnerabilities; A.5.23, information security for cloud services) are written for *vulnerabilities* in the CVE sense. A misconfiguration that's an emergent property of three healthy components isn't a CVE; it doesn't show up on a scan.

That's the temporal gap: **audits are point-in-time; modern infrastructure is continuously deployed.** The certificate describes a system that no longer exists by the time the ink dries. (AWS's own answer to this exact chain was IMDSv2, which requires a session token and breaks the naive SSRF — but that's a fix to the technology, not to the audit model that missed it.)

## Chink 2 — the perimeter gap: SolarWinds

SolarWinds was SOC 2 Type II certified. Its Orion platform was trusted network-management software running deep inside roughly **18,000** organisations, including US federal agencies.

In 2020 the attackers didn't breach those 18,000 networks. They breached *one* build server. They compromised the Orion build pipeline and injected the SUNBURST backdoor into a DLL **during compilation** — then let SolarWinds do the rest. The poisoned DLL was signed with SolarWinds' own legitimate code-signing certificate and shipped as a routine, trusted update.

```text
source repo → CI trigger → [build server ⟵ SUNBURST injected] → signed binary
            → update server (Orion) → trusted update → 18,000+ downstream orgs
```

Code signing — the control that's supposed to *prove* an update is authentic — became the delivery mechanism. Every downstream organisation verified the signature, saw a valid SolarWinds certificate, and installed the backdoor. By every rule in the book, they were *right* to trust it.

The audit failure is structural. SOC 2 Type II validates that an organisation's documented processes operated over a period of time. It does not — cannot — attest to the runtime integrity of a build server at 3 a.m. six months ago. And in 2020 no mainstream framework mandated reproducible builds or independent verification of build artefacts.

This is the supply-chain paradox: **compliance is transitive; security is not.** When you onboard a vendor you collect their SOC 2 report and tick the box — and you genuinely have inherited their *compliance*. But their certificate says nothing about whether their pipeline was compromised last Tuesday. You take on their risk without taking on any assurance about it.

## Chink 3 — the jurisdictional gap: Schrems II

This one isn't a hack at all, which is precisely the point.

In July 2020 the Court of Justice of the EU ruled in *Schrems II* (Case C-311/18) and invalidated the EU–US Privacy Shield — the framework thousands of companies relied on to move European personal data to the United States. The problem is a collision between two bodies of law that cannot both be satisfied. GDPR (Chapter V, Articles 44–46) restricts transferring EU personal data to countries without "adequate" protection. US law — FISA §702, and the CLOUD Act (18 U.S.C. §2523) — lets US authorities compel a US-headquartered provider to produce data *regardless of where in the world it is stored*.

Encrypt the data, host it in Frankfurt, sign Standard Contractual Clauses — if your provider is American, the data remains reachable by a US legal demand, and that reachability is itself the violation. Picture a concrete, very Indian version: a company in India stores its EU customers' data on AWS. On the technical checklist it is spotless:

```text
ISO 27001 ............ compliant
GDPR Article 32 ...... compliant   (encryption, access control)
SOC 2 Type II ........ compliant
Schrems II ........... NON-COMPLIANT
```

Article 32 ("security of processing") is satisfied — the data is encrypted and access-controlled. But Article 32 is about *security*; Schrems II is about *sovereignty*, and no technical audit detects a sovereignty conflict. The exposure runs up to **4% of global annual turnover**. You can pass every security audit on earth and still be breaking the law.

## Three gaps, one root cause

Three breaches, three different gaps — but one root cause, and it's the frameworks themselves. They share three properties, and each property guarantees a specific blind spot:

- They're **descriptive, not prescriptive.** They tell you *what* should exist ("a vulnerability-management process"), not *how* to verify it actually works.
- They're **trust-based, not verification-based.** A vendor's certificate is accepted as evidence about the vendor's security.
- They're **point-in-time, not continuous.** They describe a single moment, in environments that change by the hour.

And each framework was built for a world narrower than the one it's now asked to certify:

| Framework | Built for | Blind spot |
|---|---|---|
| ISO 27001:2022 | A static ISMS | Cloud runtime posture (A.5.23 is policy-level, not continuous) |
| SOC 2 Type II | Service organisations | Supply-chain depth — your vendor's vendor |
| PCI-DSS v4 | Cardholder-data scope | Cloud-native application architecture |
| COBIT 2019 | Enterprise IT governance | DevOps velocity |

## The Indian angle

India's regime has the same shape, and the same gap. The IT Act, 2000 is the spine:

- **§43A** requires a body corporate to maintain "reasonable security practices and procedures" — but "reasonable" is left technically undefined, and in practice has come to mean *holding an ISO 27001 certificate*. That quietly outsources the definition of "secure" to exactly the point-in-time framework we've just watched fail three times.
- **§70B** establishes CERT-In as the national incident-response agency.
- **§72A** penalises disclosure of personal information in breach of a lawful contract.

The 2022 CERT-In Directions sharpened the reporting duty considerably: report a cyber incident within **six hours** of noticing it, retain logs for 180 days, sync clocks to a national time source. Useful — but look at what it actually governs. It mandates *reporting* and *logging*. It says nothing about how you're meant to *detect* a breach in the first place, and it requires no continuous-monitoring infrastructure. It is a duty to confess, not a duty to see. (The DPDP Act, 2023 layers on data-fiduciary obligations, but as of 2026 its rules are still being notified.)

The fix is the same here as anywhere: move the unit of assurance from the annual snapshot to continuous monitoring — and anchor "reasonable security" in §43A to something living, like the NIST Cybersecurity Framework 2.0, rather than a certificate on a wall.

## What to actually do

Each gap has a concrete countermeasure, and not one of them is "get another certificate."

- **Temporal — monitor continuously, don't certify annually.** Treat compliance as a running query, not a yearly event. AWS Config, Azure Policy, and OpenSCAP evaluate posture against policy continuously, so drift is caught in hours instead of at the next audit.
- **Perimeter — verify, don't trust.** Demand a software bill of materials (SBOM) from vendors, prefer reproducible builds you can independently check, and treat the build pipeline as production infrastructure that needs its own monitoring. A signed binary is a claim, not a guarantee.
- **Jurisdictional — do the legal review before deployment, not after the ruling.** Where data physically lives, and which government can compel its disclosure, is an *architecture* decision. It belongs in the design review next to the threat model — not in a lawyer's letter after a court has already moved.

## Takeaways

- **A certificate describes a moment; an attacker picks a different one.** Point-in-time audits produce false negatives in any environment that changes between visits — which, now, is all of them.
- **Third-party compliance is not third-party security.** A vendor's SOC 2 tells you their process was documented, not that their build server was clean. Compliance is transitive; security isn't.
- **Technical compliance and legal compliance are different axes.** You can satisfy every control in Article 32 and still violate Chapter V. No scanner finds a sovereignty conflict.
- **The frameworks are descriptive, trust-based, and point-in-time** — three properties that each guarantee a blind spot. Knowing *which* gap a given framework leaves open is more useful than holding the certificate.
- **Compliance is a tool, not a goal.** It's a floor you clear on the way to security, never the ceiling you stop at.

*Written up from a case study for the Cyber Security Audit and Compliance course (M.Tech Cyber Security, Semester II, NFSU). Primary sources: CISA Advisory AA20-352A (SolarWinds Orion supply chain); *United States v. Paige Thompson* (Capital One); CJEU Case C-311/18 (*Schrems II*); GDPR Articles 32 & 46; the US CLOUD Act, 18 U.S.C. §2523; and the IT Act, 2000 (§§43A, 70B, 72A) with the CERT-In Directions of April 2022.*
