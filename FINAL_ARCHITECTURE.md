# Final Lookup Pipeline Architecture

## 1. Configuration model

`metadata/metadata.yaml` remains the lookup-level source of truth. Its existing structure is preserved:

- `lookup_id` and `name`
- canonical settings
- input/source files
- SIEM target enablement
- SIEM target lookup names

SIEM REST connection/deployment settings are **not** repeated per lookup. They are maintained once per SIEM in `config/deployment.yaml`.

Secrets are referenced by environment variable names in `deployment.yaml` and supplied by GitHub Actions Secrets.

## 2. Main flow

```text
Developer change
      |
      v
Detect affected lookup IDs
      |
      +--> input mode --------------------+
      |       build_canonical.py          |
      |                                    v
      +--> canonical mode ----------> validate canonical
                                       |
                                       v
                              generate_targets.py
                                       |
                                       v
                              create_manifest.py
                                       |
                                       v
                             verify branch SHA
                                       |
                                       v
                              deploy_targets.py
                                       |
                 +---------------------+---------------------+
                 |                     |                     |
              Splunk                Sentinel              Chronicle
                 |                     |                     |
                 +---------------------+---------------------+
                                       |
                                       v
                             verify branch SHA
                                       |
                                       v
                          archive input files (input mode)
                                       |
                                       v
                               commit + push
```

## 3. Manifest

For each affected lookup a versioned manifest is created at:

`generated/manifests/<lookup_id>/<version>.json`

The manifest records:

- lookup ID and name
- generation mode
- source commit SHA
- generation version
- canonical file SHA-256
- each enabled target file SHA-256 and row count
- deployment status and HTTP status for each enabled SIEM

The manifest is therefore the audit record tying one canonical/target generation to one deployment attempt.

## 4. Concurrency and immutability

The reusable generation workflow uses branch-level concurrency with `cancel-in-progress: false`.

The workflow captures the developer commit SHA and checks the remote branch immediately before and after deployment. If the branch changes, the run fails instead of pushing stale generated artifacts.

GitHub branch protection/rulesets should additionally require the lookup pipeline checks before accepting developer changes.

In canonical-edit mode the canonical file is validated and never rebuilt by `build_canonical.py`. In input mode canonical generation/merge occurs locally and is committed only after all generation and deployment steps succeed.

## 5. Deployment configuration

`config/deployment.yaml` contains SIEM-level settings such as:

- protocol
- host
- port
- endpoint
- timeout
- TLS verification
- authentication reference
- Splunk owner/namespace/backup/is-new settings

The generic Python engine does not require these values in `metadata.yaml`.

Splunk is implemented using the supplied lookup-editor REST behavior. Sentinel and Chronicle use the generic JSON adapter so their exact endpoint/payload can be configured without changing the engine.
