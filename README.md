# central-siem-lookup

# Central SIEM Lookup Pipeline

## Lookup Detection, Mode Resolution, Generation and Deployment

## 1. Overview

The Central SIEM Lookup Pipeline manages lookup data from source/input files through canonical lookup generation, SIEM-specific target generation, validation, deployment, and auditing.

The pipeline supports three important concepts:

1. **Input/source files** — files supplied by developers or upstream systems.
2. **Canonical lookup files** — normalized lookup data used as the common source for SIEM target generation.
3. **Generation mode** — determines whether the pipeline should use the input source to build the canonical lookup or use an existing canonical lookup directly.

Generation mode is resolved **independently for every Lookup ID**.

Example:

```text
LKP-001 -> input
LKP-002 -> canonical
LKP-003 -> input
```

A single global `generation_mode` must not be used because different lookups can require different processing modes in the same workflow run.

---

# 2. Repository Structure

The relevant repository structure is:

```text
central-siem-lookup/
│
├── config/
│   └── deployment.yaml
│
├── input/
│   ├── files/
│   │   ├── splunk_domain.csv
│   │   ├── splunk_malicious_ip.csv
│   │   └── sentinel_bad_ip.csv
│   │
│   └── processed/
│
├── lookups/
│   └── domain.csv
│
├── mapping/
│   ├── chronicle.yaml
│   ├── sentinel.yaml
│   └── splunk.yaml
│
├── metadata/
│   └── metadata.yaml
│
├── schema/
│   └── schema.yaml
│
├── generated/
│   ├── lookups/
│   ├── mapping/
│   ├── metadata/
│   ├── schema/
│   ├── sentinel/
│   ├── splunk/
│   └── manifests/
│
└── src/
    ├── detect_lookup.py
    ├── build_canonical.py
    ├── generate_targets.py
    ├── create_manifest.py
    ├── deploy_targets.py
    └── rollback_targets.py
```

---

# 3. Lookup Registration

`metadata/metadata.yaml` is the lookup-level source of truth.

Example:

```yaml
lookups:

  - lookup_id: LKP-001
    name: malicious_ip

    canonical:
      enabled: false
      key: indicator

    sources:
      splunk:
        file: input/files/splunk_malicious_ip.csv
      sentinel:
        file: input/files/sentinel_bad_ip.csv
      chronicle:
        file: null

    targets:
      splunk:
        enabled: true
        lookup_name: malicious_ip_lookup

      sentinel:
        enabled: true
        lookup_name: MaliciousIPWatchlist

      chronicle:
        enabled: true
        lookup_name: malicious-ip-reference-list

  - lookup_id: LKP-002
    name: domain

    canonical:
      enabled: true
      key: indicator

    sources:
      splunk:
        file: input/files/splunk_domain.csv

    targets:
      splunk:
        enabled: true
        lookup_name: domain_lookup
```

The important relationship is:

```text
LKP-002
   |
   +-- name: domain
   |
   +-- source: input/files/splunk_domain.csv
   |
   +-- canonical: lookups/domain.csv
```

The canonical filename is derived from the lookup name:

```text
lookup name = domain
canonical   = lookups/domain.csv
```

---

# 4. Change Detection

The pipeline reads the changed files from:

```text
changed_files.txt
```

Example:

```text
input/files/splunk_domain.csv
lookups/domain.csv
schema/schema.yaml
```

`src/detect_lookup.py` resolves each changed file to one or more Lookup IDs.

Supported change categories include:

* input/source file
* canonical lookup file
* schema
* mapping
* metadata
* deployment configuration
* explicit Lookup ID paths

---

# 5. Input File Detection

An input file is associated with a lookup using the `sources` section of `metadata/metadata.yaml`.

Example:

```yaml
sources:
  splunk:
    file: input/files/splunk_domain.csv
```

If:

```text
input/files/splunk_domain.csv
```

changes, the detector resolves it to:

```text
LKP-002
```

and records:

```text
LKP-002 -> input [input changed]
```

This has the highest mode precedence.

---

# 6. Canonical File Detection

Canonical files are located under:

```text
lookups/
```

The filename maps to the lookup `name`.

For example:

```text
lookups/domain.csv
```

maps to:

```text
name: domain
```

which maps to:

```text
LKP-002
```

Therefore:

```text
lookups/domain.csv
```

changing produces:

```text
LKP-002 -> canonical [canonical changed]
```

provided the canonical lookup is enabled.

---

# 7. Structural Changes

Structural changes include:

```text
schema/
mapping/
metadata/metadata.yaml
config/deployment.yaml
```

For YAML-based schema, mapping, and metadata files, the detector compares lookup entries between the base revision and the current revision.

Only affected Lookup IDs are selected.

Example:

```text
schema/schema.yaml
```

changes the definition of `LKP-002`.

The detector reports:

```text
schema/schema.yaml -> LKP-002 [schema changed]
```

Structural changes do not automatically mean `input` or `canonical`.

The final mode is determined using the mode-resolution rules described below.

---

# 8. Final Generation-Mode Precedence

Generation mode is resolved independently for every affected Lookup ID.

The rules are:

```text
1. Input file changed
      -> input

2. Canonical file changed
      -> canonical

3. Schema/mapping/metadata/config changed
      -> canonical if canonical exists
      -> input if canonical does not exist

4. Input file changed + canonical exists
      -> input
```

The key rule is:

> A changed input file always takes precedence over an existing canonical file.

Therefore, the existence of a canonical file alone does not force canonical mode.

---

# 9. Mode Resolution Algorithm

For each affected Lookup ID:

```text
if input file changed:
    mode = input

else if canonical file changed:
    mode = canonical

else if canonical file exists:
    mode = canonical

else:
    mode = input
```

The result is stored as a per-lookup mapping:

```json
{
  "LKP-001": "input",
  "LKP-002": "canonical"
}
```

This mapping is exported as:

```text
lookup_modes_json
```

It must be treated as a Lookup-ID-specific value.

---

# 10. Example 1 — Input Changed, Canonical Does Not Exist

Repository:

```text
input/files/splunk_domain.csv
```

exists and is changed.

There is no:

```text
lookups/domain.csv
```

Changed files:

```text
input/files/splunk_domain.csv
```

Result:

```text
input/files/splunk_domain.csv
    |
    +--> LKP-002
          |
          +--> input
```

Output:

```json
{
  "LKP-002": "input"
}
```

The workflow should build the canonical lookup from the input file.

---

# 11. Example 2 — Schema Changed, Canonical Exists

Files:

```text
lookups/domain.csv
schema/schema.yaml
```

`lookups/domain.csv` exists.

Only:

```text
schema/schema.yaml
```

is changed.

Result:

```text
schema/schema.yaml
    |
    +--> LKP-002
          |
          +--> canonical
```

Output:

```json
{
  "LKP-002": "canonical"
}
```

The existing canonical file is used.

`build_canonical.py` should not rebuild the canonical lookup from the input file.

---

# 12. Example 3 — Schema Changed, Canonical Does Not Exist

Changed file:

```text
schema/schema.yaml
```

There is no:

```text
lookups/domain.csv
```

Result:

```text
schema/schema.yaml
    |
    +--> LKP-002
          |
          +--> input
```

Output:

```json
{
  "LKP-002": "input"
}
```

Because there is no canonical lookup to validate/use, the input source becomes the generation source.

---

# 13. Example 4 — Input Changed and Canonical Exists

This is the important case.

Repository contains:

```text
input/files/splunk_domain.csv
lookups/domain.csv
```

Both exist.

The input file changes:

```text
input/files/splunk_domain.csv
```

Result:

```text
input changed
     |
     v
LKP-002
     |
     v
input
```

Output:

```json
{
  "LKP-002": "input"
}
```

Even though:

```text
lookups/domain.csv
```

exists, the mode is still:

```text
input
```

because an input change has higher precedence.

The expected workflow behavior is:

```text
input/files/splunk_domain.csv
            |
            v
   build_canonical.py
            |
            v
   lookups/domain.csv
            |
            v
   generate SIEM targets
```

---

# 14. Example 5 — Input and Schema Both Changed

Files:

```text
input/files/splunk_domain.csv
schema/schema.yaml
```

are both changed.

Whether or not:

```text
lookups/domain.csv
```

exists, the input change wins.

Result:

```json
{
  "LKP-002": "input"
}
```

Reason:

```text
input changed
    >
schema changed
```

The pipeline rebuilds the canonical lookup from the updated input.

---

# 15. Example 6 — Canonical and Schema Both Changed

Files:

```text
lookups/domain.csv
schema/schema.yaml
```

are changed.

No input file changed.

Result:

```json
{
  "LKP-002": "canonical"
}
```

The canonical file is treated as the authoritative changed artifact.

The pipeline validates it and generates SIEM targets from it.

---

# 16. Example 7 — Input, Canonical and Schema All Changed

Files:

```text
input/files/splunk_domain.csv
lookups/domain.csv
schema/schema.yaml
```

are all changed.

Result:

```json
{
  "LKP-002": "input"
}
```

Reason:

```text
input changed
    >
canonical changed
    >
schema changed
```

The input source wins.

The workflow rebuilds/merges the canonical lookup from the updated input.

The canonical file is therefore not treated as an independent authoritative source for this run.

---

# 17. Example 8 — Multiple Lookup IDs

Suppose the repository contains:

```text
LKP-001 -> malicious_ip
LKP-002 -> domain
```

and the changes are:

```text
input/files/splunk_malicious_ip.csv
schema/schema.yaml
```

Assume:

```text
lookups/malicious_ip.csv does not exist
lookups/domain.csv exists
```

The result can be:

```json
{
  "LKP-001": "input",
  "LKP-002": "canonical"
}
```

This demonstrates why generation mode must be per Lookup ID.

The same workflow run can process:

```text
LKP-001 -> input
LKP-002 -> canonical
```

independently.

---

# 18. Example 9 — Current Test Case

Given:

```text
lookups/domain.csv                  exists
input/files/splunk_domain.csv       exists and changed
schema/schema.yaml                  changed
```

The detector should report:

```text
Changed files:
  input/files/splunk_domain.csv
  lookups/domain.csv
  schema/schema.yaml
```

Resolution:

```text
input/files/splunk_domain.csv -> LKP-002 [input changed]
lookups/domain.csv            -> LKP-002 [canonical changed]
schema/schema.yaml            -> LKP-002 [schema changed]
```

Final mode:

```text
LKP-002 -> input [input changed]
```

Final output:

```text
Lookup modes: {"LKP-002": "input"}
```

The input change wins over the canonical and schema changes.

---

# 19. Detector Output

A successful detection run looks like:

```text
======================================
Lookup detection started
======================================

Registered lookups:
  LKP-001 -> malicious_ip
  LKP-002 -> domain

Changed files:
  input/files/splunk_domain.csv
  schema/schema.yaml

Resolution:
--------------------------------------
input/files/splunk_domain.csv -> LKP-002 [input changed]
schema/schema.yaml -> LKP-002 [schema changed]

Mode resolution:
  LKP-002 -> input [input changed]

======================================
Affected Lookup IDs
======================================
  LKP-002
======================================
CSV: LKP-002
JSON: ["LKP-002"]
Lookup modes: {"LKP-002": "input"}
```

For a schema-only change where the canonical exists:

```text
Mode resolution:
  LKP-002 -> canonical [canonical exists]
```

and:

```text
Lookup modes: {"LKP-002": "canonical"}
```

---

# 20. GitHub Actions Outputs

The detector writes the following outputs to `GITHUB_OUTPUT`:

```text
lookup_ids
lookup_ids_json
lookup_count
lookup_modes_json
```

Example:

```text
lookup_ids=LKP-001,LKP-002
```

```json
["LKP-001", "LKP-002"]
```

```text
lookup_count=2
```

```json
{
  "LKP-001": "input",
  "LKP-002": "canonical"
}
```

Downstream workflow steps must use `lookup_modes_json` to determine the mode for each Lookup ID.

They must not assume that all affected lookups share the same mode.

---

# 21. Input Mode Processing

When a Lookup ID is resolved to:

```text
input
```

the workflow uses the input source to build/update the canonical lookup.

Conceptually:

```text
Input CSV
   |
   v
build_canonical.py
   |
   v
Canonical CSV
   |
   v
Validation
   |
   v
SIEM target generation
```

Example:

```text
input/files/splunk_domain.csv
        |
        v
lookups/domain.csv
        |
        +--> Splunk target
        +--> Sentinel target
        +--> Chronicle target
```

Only enabled SIEM targets are generated/deployed.

---

# 22. Canonical Mode Processing

When a Lookup ID is resolved to:

```text
canonical
```

the workflow uses the existing canonical lookup.

Conceptually:

```text
Existing canonical CSV
          |
          v
      Validation
          |
          v
 SIEM target generation
          |
          v
       Deployment
```

`build_canonical.py` should not rebuild the canonical file in this mode.

---

# 23. Input File Archiving

Input files are archived only for lookups that were actually processed in `input` mode.

This prevents an unchanged input file from being incorrectly archived merely because another file, such as a schema, changed.

For example:

```text
LKP-002 -> input
```

means the relevant input source may be archived after successful generation and deployment.

If:

```text
LKP-002 -> canonical
```

the input source should not be archived merely because the lookup was processed.

---

# 24. Canonical File Existence

Canonical mode is based on the actual filesystem state.

For lookup:

```text
name: domain
```

the detector checks:

```text
lookups/domain.csv
```

Existence of:

```yaml
canonical:
  enabled: true
```

alone is not sufficient to force canonical mode.

The following distinction is important:

```text
canonical.enabled = configuration
lookups/domain.csv = actual canonical artifact
```

For structural changes:

```text
canonical exists
    -> canonical

canonical missing
    -> input
```

However, if the input file itself changed, the input-change rule takes precedence regardless of canonical existence.

---

# 25. Complete Decision Table

| Input changed | Canonical changed | Structural changed | Canonical exists | Final mode   |
| ------------- | ----------------- | ------------------ | ---------------- | ------------ |
| Yes           | No                | No                 | No               | `input`      |
| Yes           | No                | No                 | Yes              | `input`      |
| Yes           | Yes               | No                 | Yes              | `input`      |
| Yes           | No                | Yes                | Yes              | `input`      |
| Yes           | Yes               | Yes                | Yes              | `input`      |
| No            | Yes               | No                 | Yes              | `canonical`  |
| No            | Yes               | Yes                | Yes              | `canonical`  |
| No            | No                | Yes                | Yes              | `canonical`  |
| No            | No                | Yes                | No               | `input`      |
| No            | No                | No                 | Yes              | Not affected |
| No            | No                | No                 | No               | Not affected |

The critical precedence is:

```text
INPUT CHANGE
     ↓
CANONICAL CHANGE
     ↓
STRUCTURAL CHANGE
```

with canonical existence used to resolve structural-only changes.

---

# 26. Recommended Operational Rule

The simplest way to understand the system is:

> **If the developer changed the input, regenerate from input. If the developer changed the canonical lookup, use canonical. If only the structure changed, use canonical when it exists; otherwise use input.**

This guarantees that a newly changed source file is never ignored simply because an older canonical file happens to exist.

---

# 27. End-to-End Pipeline

The complete flow is:

```text
Developer Commit
       |
       v
changed_files.txt
       |
       v
detect_lookup.py
       |
       +-----------------------------+
       |                             |
       v                             v
Affected Lookup IDs           Per-Lookup Mode
                              |
               +--------------+--------------+
               |                             |
             input                       canonical
               |                             |
               v                             v
      build_canonical.py             Validate canonical
               |                             |
               +--------------+--------------+
                              |
                              v
                    generate_targets.py
                              |
                              v
                     create_manifest.py
                              |
                              v
                       Verify branch SHA
                              |
                              v
                       deploy_targets.py
                              |
                +-------------+-------------+
                |             |             |
             Splunk        Sentinel      Chronicle
                |             |             |
                +-------------+-------------+
                              |
                              v
                       Verify branch SHA
                              |
                              v
                    Archive input files
                    for input-mode runs
                              |
                              v
                         Commit + Push
```

---

# 28. Audit Manifest

Each affected lookup receives a versioned manifest:

```text
generated/manifests/<lookup_id>/<version>.json
```

The manifest records information such as:

* Lookup ID
* Lookup name
* generation mode
* source commit SHA
* generation version
* canonical file SHA-256
* generated target file SHA-256
* row counts
* deployment status
* HTTP status for enabled SIEMs

Example:

```json
{
  "lookup_id": "LKP-002",
  "lookup_name": "domain",
  "generation_mode": "input",
  "source_commit": "abc123...",
  "canonical_sha256": "...",
  "targets": {
    "splunk": {
      "sha256": "...",
      "rows": 125
    }
  }
}
```

This provides an audit trail connecting the developer change to the generated artifacts and deployment attempt.

---

# 29. Concurrency and Safety

The generation workflow uses branch-level concurrency with:

```text
cancel-in-progress: false
```

The workflow captures the developer commit SHA and verifies the branch before and after deployment.

If the branch changes during processing, the workflow must fail rather than pushing artifacts generated from a stale revision.

This prevents stale generated artifacts from overwriting newer developer changes.

---

# 30. Summary

The final generation-mode behavior is:

```text
┌──────────────────────────────────────────────┐
│          Has input file changed?             │
└──────────────────────┬───────────────────────┘
                       │
                 Yes   │   No
                       │
                       v
                    INPUT
                       │
                       │
                       No
                       v
┌──────────────────────────────────────────────┐
│       Has canonical file changed?            │
└──────────────────────┬───────────────────────┘
                       │
                 Yes   │   No
                       │
                       v
                  CANONICAL
                       │
                       │
                       No
                       v
┌──────────────────────────────────────────────┐
│          Does canonical file exist?           │
└──────────────────────┬───────────────────────┘
                       │
                 Yes   │   No
                       │
                       v
                  CANONICAL       INPUT
```

### Final precedence

```text
input changed
    >
canonical changed
    >
structural change + canonical exists
    >
structural change + canonical missing
```

Or, in one sentence:

**A changed input always wins; otherwise a changed canonical wins; otherwise structural changes use the canonical file when it exists, and fall back to input when it does not.**
