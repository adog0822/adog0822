# LoxeAI — Self-Driving SOC 2

> Every SaaS startup needs SOC 2 to sell into enterprise. But SOC 2 sucks — it's busywork, spreadsheets, and chasing evidence. Founders don't want compliance teams; they want SOC 2 to disappear.
>
> **LoxeAI makes SOC 2 disappear.**

The compliance prep layer for every company, from pre-idea to pre-IPO. Audit-ready in days, not months.

---

## Core Principles

| Pillar | What it means |
|--------|---------------|
| **Simplicity** | One-click, one-shot workflows. Premium minimalism. Language & translation seamless via Gideon co-pilot. |
| **Verifiability** | Every evidence item traced to the API call that produced it. SHA-256 hashed, timestamped, cryptographically chained. |
| **Customization** | 54 pre-approved control templates. Parameter-driven. Multi-entity workspaces. Deterministic execution. |

## Architecture

```
src/
├── types/              # Branded TypeScript types for the entire platform
├── core/
│   ├── ibac/           # Intent-Based Access Control engine
│   │   ├── intent-parser.ts       # NL → IntentObject (Action, Resource, Context, Risk)
│   │   ├── evaluation-engine.ts   # Deterministic control template evaluation
│   │   ├── middleware.ts          # IBAC interception + crypto evidence binding
│   │   └── default-controls.ts   # 15+ default IBAC control templates
│   └── evidence/
│       └── crypto-chain.ts       # SHA-256 hash chains, verification, evidence ledger
├── soc2/
│   ├── controls/
│   │   └── registry.ts           # All 33 Common Criteria (CC1-CC9)
│   ├── mapping/
│   │   ├── evidence-mapper.ts    # Cloud findings → SOC 2 control mapping
│   │   └── control-scorer.ts     # Weighted scoring per control
│   └── templates/
│       └── control-templates.ts  # 54 customizable check templates
├── integrations/
│   ├── aws/
│   │   └── scanner.ts            # 10 AWS security scans (IAM, S3, CloudTrail, etc.)
│   ├── github/
│   │   └── scanner.ts            # 5 GitHub org security scans
│   ├── evidence-collector.ts     # Orchestrates scanning across all integrations
│   └── registry.ts               # 17 supported integrations with metadata
├── onboarding/
│   ├── questions.ts              # 20-question onboarding bank across 6 sections
│   ├── engine.ts                 # State machine driving the questionnaire flow
│   ├── agent-orchestrator.ts     # Background agent lifecycle for integration scans
│   └── aws-setup.ts              # CloudFormation template + cross-account role setup
├── api/
│   ├── routes/                   # REST API handlers for all platform operations
│   │   ├── onboarding.ts         # Onboarding session management
│   │   ├── evidence.ts           # Evidence inventory, scanning, blacklisting
│   │   ├── controls.ts           # SOC 2 control dashboard and template config
│   │   ├── auditor.ts            # Auditor sessions, grading, evidence packages
│   │   ├── gideon.ts             # "Ask Gideon" compliance co-pilot
│   │   ├── ibac.ts               # IBAC evaluation and audit log
│   │   └── remediation.ts        # Remediation workflow management
│   └── middleware/
│       ├── ibac-middleware.ts     # IBAC interception layer
│       └── auth-middleware.ts     # Session auth + auditor time-bound access
├── auditor/
│   └── workflow.ts               # Evidence packages, fieldwork sampling, grading,
│                                 # cross-framework mapping (SOC 2 → ISO → NIST),
│                                 # one-click workpaper export
└── copilot/
    └── gideon.ts                 # "Ask Gideon" — Plain English + Engineer + Auditor
                                  # perspectives, control mapping, action suggestions
```

## Key Features

### Intent-Based Access Control (IBAC)
Traditional RBAC is insufficient for agentic workflows. IBAC intercepts all natural language prompts, agent plans, and API actions *before* execution:

1. **Intent Parser** — Translates "update our firewall policy" into `{action: "modify", resource: "firewall_template", riskLevel: "high"}`
2. **Evaluation Engine** — Matches intent against workspace-customized control templates deterministically
3. **Middleware** — Hashes the entire decision chain (intent + evaluation + result) into the evidence ledger

### Cryptographic Evidence Chain
Every API call is recorded with:
- SHA-256 hash of the response
- Blockchain-style hash chain (each hash includes the previous)
- Timestamp, request ID, status code
- Full chain verification (detect any tampering)

### Onboarding Questionnaire
20 questions across 6 sections. As users check integrations, background agents spin up to collect evidence *while they're still answering questions*. By the time they finish, evidence is already mapped.

### AWS Integration
CloudFormation template creates a read-only IAM role with SecurityAudit + ViewOnlyAccess. The scanner covers IAM, S3, CloudTrail, VPC, RDS, KMS, GuardDuty, Config, and Backup.

### Auditor Workflow
- Time-bound, scope-limited sessions
- Automated evidence packages (zero uploads)
- Full-population fieldwork sampling with anomaly detection
- Cross-framework mapping (SOC 2 → ISO 27001 → NIST CSF → NIST 800-53)
- One-click workpaper export (AICPA/OSCAL)

### Gideon Co-Pilot
Highlight any text → get three perspectives:
1. **Plain English** — what does this actually mean?
2. **What Engineers Should Hear** — actionable technical guidance
3. **Why Auditors Care** — SOC 2 Trust Services Criteria context

## Core Attributes

- **Deterministic execution** — no probabilistic agent drift
- **Intent-governed actions** — IBAC instead of RBAC
- **Cryptographically verifiable evidence** — every action hashed, timestamped, chained
- **Parameter-driven controls** — customizable, replayable, auditable
- **Minimalist UX** — one-click, one-shot workflows
- **Read-only integrations** — safe by design
- **Multi-entity governance** — workspace-level customization

## Development

```bash
npm install
npm run dev        # Start development server
npm run typecheck  # TypeScript validation
npm run test       # Run test suite
```

---

*LoxeAI: Self-Driving SOC 2. The compliance prep layer from pre-idea to pre-IPO.*
