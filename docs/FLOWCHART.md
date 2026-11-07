# Flowcharts

All layers converge on the same pipeline: **event → scan → alert → remediation**. Diagrams use [Mermaid](https://mermaid.js.org/) syntax and render on most modern markdown viewers.

## Unified flow

```mermaid
flowchart TD
    E["Event: file save, diff, export, API page, mtime change"] --> S["Scan: shared detector registry<br/>regex + entropy + validators"]
    S --> A{"Allowlisted?"}
    A -->|yes| X["Drop: known false positive"]
    A -->|no| M["Mask secret + SHA-256 fingerprint"]
    M --> D{"Already stored?<br/>fingerprint + path + line"}
    D -->|known| U["Update updated_at, keep status"]
    D -->|new| DB["Store finding in SQLite"]
    DB --> EV["Record event"]
    EV --> W{"Alert sent within<br/>dedupe window?"}
    W -->|yes| SKIP["Skip alert"]
    W -->|no| AL["Alert: console, outbox,<br/>Slack webhook, generic webhook"]
    AL --> T["Triage: GPT or heuristic fallback"]
    T --> R{"Remediation action"}
    R -->|rotate-guide| RG["Markdown playbook<br/>status: triaged"]
    R -->|ticket| TK["Jira ticket or outbox draft<br/>status: triaged"]
    R -->|redact| RD["In-place REDACTED replacement<br/>status: remediated"]
    R -->|quarantine| Q["Move file to data/quarantine<br/>status: remediated"]
    T -->|confirmed false positive| FP["Allowlist fingerprint<br/>status: false_positive"]
```

## Layer 1: local development (IDE, watch, git hooks)

```mermaid
flowchart TD
    subgraph local ["Local machine only - no network required"]
        IDE["Editor saves a file"] --> IS["ingest --surface ide --file PATH"]
        WT["watch PATH polls mtimes"] --> CH{"File changed?"}
        CH -->|yes| WS["Scan changed file"]
        PC["git commit"] --> H1["pre-commit hook"]
        H1 --> G1["gate --staged"]
        PP["git push"] --> H2["pre-push hook"]
        H2 --> G2["gate --range remote..local"]
    end
    IS --> P["Shared pipeline: scan, dedupe, store, alert"]
    WS --> P
    G1 --> B1{"Findings at or above fail_on?"}
    G2 --> B2{"Findings at or above fail_on?"}
    B1 -->|yes| BLOCK1["Exit 1: commit blocked"]
    B1 -->|no| OK1["Exit 0: commit allowed"]
    B2 -->|yes| BLOCK2["Exit 1: push blocked"]
    B2 -->|no| OK2["Exit 0: push allowed"]
    G1 --> P
    G2 --> P
```

## Layer 2: CI diff gate

```mermaid
flowchart TD
    CI["CI job: GitHub Actions, GitLab CI, or Jenkins"] --> CO["Checkout with base branch available"]
    CO --> G["gate --base origin/main --head HEAD<br/>or gate --range BASE..HEAD"]
    G --> DIFF["git diff --unified=0: added lines only"]
    DIFF --> SCAN["Shared detector registry on each added line"]
    SCAN --> IGN["Filter ignored dirs + allowlist"]
    IGN --> ING["Ingest: record gate.blocked or gate.passed event"]
    ING --> TH{"Any finding at or above<br/>scan.fail_on (default high)?"}
    TH -->|yes| FAIL["Exit 1: pipeline fails<br/>fix or allowlist confirmed false positives"]
    TH -->|no| PASS["Exit 0: pipeline proceeds"]
```

## Layer 3: cloud / Lambda

```mermaid
flowchart TD
    START["ingest --surface cloud"] --> MODE{"surfaces.cloud.provider"}
    MODE -->|local| LOC["Scan lambda_dir (default examples/lambda)"]
    LOC --> CFG["Each function config.json:<br/>Environment.Variables"]
    LOC --> CODE["Function code: .py and .js files"]
    MODE -->|aws| AWS{"boto3 installed and<br/>AWS credentials present?"}
    AWS -->|no| FALL["Fall back to local scan"]
    AWS -->|yes| LIVE["List Lambda functions, read env config"]
    CFG --> SCAN["Shared detector registry"]
    CODE --> SCAN
    LIVE --> SCAN
    FALL --> LOC
    SCAN --> P["Shared pipeline: dedupe, store, alert"]
    P --> REM["Remediate: rotate guide, ticket,<br/>update function configuration"]
```

## Layer 4: SaaS monitoring (Slack, Confluence, Jira, Postman)

```mermaid
flowchart TD
    START["ingest --surface slack | confluence | jira | postman | postman-env"] --> SRC{"--file provided?"}
    SRC -->|yes| EXP["Load JSON export fixture"]
    SRC -->|no| TOK{"Token and base URL configured?"}
    TOK -->|no| EMPTY["No live source: nothing scanned"]
    TOK -->|yes| API["Live REST polling with pagination<br/>and rate limiting"]
    EXP --> TXT["Extract text: messages, page bodies,<br/>issue fields, collection strings, env values"]
    API --> TXT
    TXT --> SCAN["Shared detector registry"]
    SCAN --> P["Shared pipeline: dedupe, store, alert"]
    P --> OWN["Owner attribution from source metadata"]
    OWN --> REM["Remediate: rotate, delete exposure,<br/>ticket to channel or project owner"]
```

## Status lifecycle

```mermaid
flowchart LR
    O["open"] -->|triage, rotate-guide, ticket| T["triaged"]
    T -->|redact, quarantine| R["remediated"]
    O -->|allowlist fingerprint| F["false_positive"]
    T -->|allowlist fingerprint| F
```

## Reference workflows (per-layer parity)

These diagrams mirror the reference architecture the project follows: every
surface converges on one findings store, every secret is detected, alerted and
followed up, and each finding carries provenance answering "how did that get
there?".

### All surfaces converge

```mermaid
flowchart TD
    subgraph before["Before code leaves"]
        IDE["IDE: accidental paste"]
        PP["Pre-push: left in, plan to fix"]
        JC["Jira / Confluence: debug paste"]
        SL["Slack: key in message"]
    end
    subgraph pipeline["Pipeline and more"]
        PR["Push / PR: secret in commit or diff"]
        CI["Git / CI: forgot to remove"]
        LA["Lambda: hardcoded code or env"]
        PM["Postman: key in collection or env"]
    end
    IDE --> ALL["All surfaces"]
    PP --> ALL
    JC --> ALL
    SL --> ALL
    PR --> ALL
    CI --> ALL
    LA --> ALL
    PM --> ALL
    ALL --> DET["Secrets escaping: detect, alert, follow up"]
    DET --> PROV["How did that get there?<br/>provenance: surface, event, commit, author"]
```

### Dev env secrets scanning

```mermaid
flowchart LR
    W["Developer writes code"] --> M["Scanner triggers manually on demand"]
    W --> A["Scanner triggers automatically on file save"]
    M --> L["Local scanner detects secrets in code"]
    A --> L
    L --> I["Alerts displayed inline in IDE"]
```

### Pre-push checks

```mermaid
flowchart LR
    P["Developer pushes code"] --> H["Pre-push hook scans commits for secrets"]
    H --> D{"Secret detected?"}
    D -->|no| OK["Push succeeds"]
    D -->|yes| BL["Push blocked - file and line shown"]
```

### Pull request checks

```mermaid
flowchart LR
    PR["Pull request opened or updated"] --> S["Secret scanner evaluates PR diff"]
    S -->|no issues| MA["Merge allowed"]
    S -->|secrets detected| MB["Merge blocked"]
    MB --> N["Developer notified immediately"]
```

### Jira / Confluence monitoring

```mermaid
flowchart LR
    J["Jira or Confluence"] --> E["Event trigger"]
    E --> S["Scan for secrets"]
    S --> C{"Finding confirmed?"}
    C -->|no| IG["Ignore / log for audit"]
    C -->|yes| G["Generate security finding"]
    G --> N["Notify user"]
```

### Slack monitoring

```mermaid
flowchart LR
    M["Message posted"] --> R["Scanner reads content"]
    R --> S["Scan for secrets"]
    S --> D{"Secret detected?"}
    D -->|yes| N["Notify user"]
    D -->|no| Q["No action"]
```

### End-to-end architecture

```mermaid
flowchart TD
    subgraph dev["Developer"]
        PH["Pre-push hook"]
        IS["IDE scan"]
    end
    subgraph gh["GitHub"]
        PU["Push"] --> GS["Push secret scan"]
        PO["PR open/update"] --> PC["PR scan CI"]
    end
    subgraph cloud["Serverless and cloud functions"]
        LS["Lambda scanner"]
    end
    subgraph saas["SaaS and collaboration"]
        PM["Postman monitor"]
        SS["Slack scanner"]
        CS["Confluence scanner"]
        JS["Jira scanner"]
    end
    subgraph alert["Alerting and remediation"]
        FS[("Findings store")]
        JT["Jira tickets"]
        SP["Slack channel: post + mention user"]
    end
    PH -->|block push| PU
    IS --> GS
    GS --> FS
    PC --> FS
    LS --> FS
    PM --> FS
    SS --> FS
    CS --> FS
    JS --> FS
    FS --> JT
    FS -->|every secret| SP
    FS --> TA["triage_alerts sweep"]
    TA -->|feedback| dev
```