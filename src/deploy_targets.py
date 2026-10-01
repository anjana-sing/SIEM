import argparse
import csv
import json
import os
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import yaml


# ============================================================================
# Configuration
# ============================================================================

DEPLOYMENT_FILE = Path("config/deployment.yaml")
METADATA_FILE = Path("metadata/metadata.yaml")
MANIFEST_ROOT = Path("generated/manifests")

SUPPORTED_SIEMS = (
    "splunk",
    "sentinel",
    "chronicle",
)


# ============================================================================
# Exception
# ============================================================================

class DeploymentError(Exception):
    pass


# ============================================================================
# YAML
# ============================================================================

def load_yaml(path):
    if not path.exists():
        raise DeploymentError(
            f"Required file not found: {path}"
        )

    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except yaml.YAMLError as exc:
        raise DeploymentError(
            f"Invalid YAML in {path}: {exc}"
        ) from exc


# ============================================================================
# Environment variable expansion
# ============================================================================

def expand(value):
    """
    Recursively replace:

        ${VARIABLE_NAME}

    with the corresponding environment variable.
    """

    if isinstance(value, str):
        pattern = r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}"

        return re.sub(
            pattern,
            lambda match: os.environ.get(
                match.group(1),
                match.group(0),
            ),
            value,
        )

    if isinstance(value, dict):
        return {
            key: expand(val)
            for key, val in value.items()
        }

    if isinstance(value, list):
        return [
            expand(item)
            for item in value
        ]

    return value


# ============================================================================
# Load target rows
# ============================================================================

def load_rows(path):
    """
    Load a generated target CSV or JSON file.

    CSV result:

        [
            {
                "domain": "qa-example.org",
                "category": "c2",
                ...
            }
        ]

    JSON result must be an array.
    """

    if not path.exists():
        raise DeploymentError(
            f"Target file not found: {path}"
        )

    # ------------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------------

    if path.suffix.lower() == ".json":

        try:
            with open(
                path,
                "r",
                encoding="utf-8",
            ) as f:
                data = json.load(f)

        except json.JSONDecodeError as exc:
            raise DeploymentError(
                f"Invalid JSON target file {path}: {exc}"
            ) from exc

        if not isinstance(data, list):
            raise DeploymentError(
                f"Target JSON must contain an array: {path}"
            )

        return data

    # ------------------------------------------------------------------------
    # CSV
    # ------------------------------------------------------------------------

    try:
        with open(
            path,
            "r",
            encoding="utf-8-sig",
            newline="",
        ) as f:
            return list(
                csv.DictReader(f)
            )

    except csv.Error as exc:
        raise DeploymentError(
            f"Invalid CSV target file {path}: {exc}"
        ) from exc


# ============================================================================
# Convert rows to Splunk matrix
# ============================================================================

def rows_to_matrix(rows):
    """
    Convert CSV DictReader output into the 2D list expected by
    the tested Splunk Lookup Editor API.

    Input:

        [
            {
                "id": "104",
                "name": "abc"
            },
            {
                "id": "107",
                "name": "xyz"
            }
        ]

    Output:

        [
            ["id", "name"],
            ["104", "abc"],
            ["107", "xyz"]
        ]
    """

    if not rows:
        return []

    # If JSON was supplied as a matrix already, preserve it.
    if isinstance(rows[0], list):
        return rows

    if not isinstance(rows[0], dict):
        raise DeploymentError(
            "Lookup rows must contain dictionaries or lists"
        )

    # Preserve the column order from the generated CSV.
    headers = list(rows[0].keys())

    data = [headers]

    for row in rows:
        data.append([
            "" if row.get(header) is None
            else row.get(header, "")
            for header in headers
        ])

    return data


# ============================================================================
# Template rendering
# ============================================================================

def render_template(
    value,
    lookup_name,
    rows,
):
    """
    Supported placeholders:

        ${LOOKUP_NAME}
        ${ROWS_JSON}
        ${ROWS_JSON_PRETTY}
    """

    rows_json = json.dumps(
        rows,
        separators=(",", ":"),
    )

    rows_text = json.dumps(
        rows,
        indent=2,
    )

    if isinstance(value, str):
        return (
            value
            .replace(
                "${LOOKUP_NAME}",
                lookup_name,
            )
            .replace(
                "${ROWS_JSON}",
                rows_json,
            )
            .replace(
                "${ROWS_JSON_PRETTY}",
                rows_text,
            )
        )

    if isinstance(value, dict):
        return {
            key: render_template(
                val,
                lookup_name,
                rows,
            )
            for key, val in value.items()
        }

    if isinstance(value, list):
        return [
            render_template(
                item,
                lookup_name,
                rows,
            )
            for item in value
        ]

    return value


# ============================================================================
# Authentication
# ============================================================================

def auth_headers(config):
    """
    Supported authentication types:

        none
        bearer
    """

    auth = config.get(
        "authentication"
    ) or {}

    auth_type = str(
        auth.get("type", "none")
    ).lower()

    # ------------------------------------------------------------------------
    # No authentication
    # ------------------------------------------------------------------------

    if auth_type == "none":
        return {}

    # ------------------------------------------------------------------------
    # Bearer token
    # ------------------------------------------------------------------------

    if auth_type != "bearer":
        raise DeploymentError(
            f"Unsupported authentication type: {auth_type}"
        )

    token_env = auth.get(
        "token_env"
    )

    if not token_env:
        raise DeploymentError(
            "authentication.token_env is required"
        )

    token = os.environ.get(
        token_env
    )

    if not token:
        raise DeploymentError(
            f"Required authentication secret is not set: "
            f"{token_env}"
        )

    prefix = auth.get(
        "prefix",
        "Bearer",
    )

    if prefix:
        return {
            "Authorization":
                f"{prefix} {token}"
        }

    return {
        "Authorization": token
    }


# ============================================================================
# REST URL
# ============================================================================

def base_url(config):
    protocol = str(
        config.get(
            "protocol",
            "https",
        )
    ).lower()

    host = config.get("host")
    port = config.get("port")
    endpoint = config.get("endpoint")

    if (
        not host
        or not endpoint
        or "${" in str(host)
        or "${" in str(endpoint)
    ):
        raise DeploymentError(
            "Deployment config requires resolved host and endpoint; "
            "check deployment.yaml and GitHub environment variables"
        )

    if not endpoint.startswith("/"):
        endpoint = "/" + endpoint

    default_port = {
        "http": 80,
        "https": 443,
    }.get(protocol)

    if port in (
        None,
        "",
        default_port,
    ):
        netloc = str(host)
    else:
        netloc = f"{host}:{port}"

    return (
        f"{protocol}://"
        f"{netloc}"
        f"{endpoint}"
    )


# ============================================================================
# REST request
# ============================================================================

def request(
    config,
    headers,
    data=None,
    form=False,
):
    url = base_url(config)

    method = str(
        config.get(
            "method",
            "POST",
        )
    ).upper()

    timeout = int(
        config.get(
            "timeout",
            60,
        )
    )

    verify_ssl = bool(
        config.get(
            "verify_ssl",
            True,
        )
    )

    request_headers = dict(
        headers or {}
    )

    # ------------------------------------------------------------------------
    # Form encoded request
    # ------------------------------------------------------------------------

    if form:

        body = urllib.parse.urlencode(
            data or {}
        ).encode("utf-8")

        request_headers.update({
            "Content-Type":
                "application/x-www-form-urlencoded",
            "Accept":
                "application/json",
        })

    # ------------------------------------------------------------------------
    # JSON request
    # ------------------------------------------------------------------------

    else:

        body = json.dumps(
            data
            if data is not None
            else {}
        ).encode("utf-8")

        request_headers.update({
            "Content-Type":
                "application/json",
            "Accept":
                "application/json",
        })

    req = urllib.request.Request(
        url,
        data=body,
        headers=request_headers,
        method=method,
    )

    # ------------------------------------------------------------------------
    # SSL
    # ------------------------------------------------------------------------

    if verify_ssl:
        context = ssl.create_default_context()
    else:
        context = ssl._create_unverified_context()

    # ------------------------------------------------------------------------
    # Execute
    # ------------------------------------------------------------------------

    try:

        with urllib.request.urlopen(
            req,
            timeout=timeout,
            context=context,
        ) as response:

            payload = response.read().decode(
                "utf-8",
                errors="replace",
            )

            return (
                response.status,
                payload,
            )

    except urllib.error.HTTPError as exc:

        payload = exc.read().decode(
            "utf-8",
            errors="replace",
        )

        raise DeploymentError(
            f"HTTP {exc.code} from {url}: "
            f"{payload[:2000]}"
        ) from exc

    except urllib.error.URLError as exc:

        raise DeploymentError(
            f"REST request failed for {url}: "
            f"{exc}"
        ) from exc


# ============================================================================
# Splunk deployment
# ============================================================================

def deploy_splunk(
    config,
    lookup_name,
    rows,
):
    """
    Deploy lookup to Splunk Lookup Editor.

    This follows the tested implementation:

        data = [
            ["id", "name"],
            ["104", "abc"],
            ["107", "xyz"]
        ]

        payload = {
            "lookup_file": "test1.csv",
            "contents": json.dumps(data),
            ...
        }
    """

    # ------------------------------------------------------------------------
    # Convert generated CSV rows into the exact matrix format expected
    # by the tested Splunk API call.
    # ------------------------------------------------------------------------

    data = rows_to_matrix(rows)

    # ------------------------------------------------------------------------
    # Build Splunk payload
    # ------------------------------------------------------------------------

    payload = {
        "lookup_file":
            lookup_name + ".csv",

        "contents":
            json.dumps(data),

        "namespace":
            config.get(
                "namespace",
                "search",
            ),

        "owner":
            config.get(
                "owner",
                "nobody",
            ),

        "backup":
            str(
                bool(
                    config.get(
                        "backup",
                        False,
                    )
                )
            ).lower(),

        "isNew":
            str(
                bool(
                    config.get(
                        "is_new",
                        False,
                    )
                )
            ).lower(),
    }

    # ------------------------------------------------------------------------
    # Send form-urlencoded request
    # ------------------------------------------------------------------------

    return request(
        config,
        auth_headers(config),
        data=payload,
        form=True,
    )


# ============================================================================
# Generic JSON deployment
# ============================================================================

def deploy_generic(
    config,
    lookup_name,
    rows,
):
    payload = render_template(
        config.get(
            "payload",
            {
                "lookup_name":
                    "${LOOKUP_NAME}",

                "rows":
                    "${ROWS_JSON}",
            },
        ),
        lookup_name,
        rows,
    )

    return request(
        config,
        auth_headers(config),
        data=payload,
        form=False,
    )


# ============================================================================
# Deploy one SIEM target
# ============================================================================

def deploy_one(
    siem,
    config,
    lookup_name,
    rows,
):
    # ------------------------------------------------------------------------
    # Deployment disabled
    # ------------------------------------------------------------------------

    if not config.get(
        "enabled",
        True,
    ):
        return {
            "status": "skipped",
            "http_status": None,
            "message":
                "Deployment disabled in deployment.yaml",
        }

    adapter = config.get(
        "adapter",
        siem,
    )

    # ------------------------------------------------------------------------
    # Splunk
    # ------------------------------------------------------------------------

    if adapter == "splunk":

        status, body = deploy_splunk(
            config,
            lookup_name,
            rows,
        )

    # ------------------------------------------------------------------------
    # Generic JSON
    # ------------------------------------------------------------------------

    elif adapter == "generic_json":

        status, body = deploy_generic(
            config,
            lookup_name,
            rows,
        )

    else:

        raise DeploymentError(
            f"Unsupported deployment adapter "
            f"for {siem}: {adapter}"
        )

    # ------------------------------------------------------------------------
    # Validate HTTP response
    # ------------------------------------------------------------------------

    if status < 200 or status >= 300:

        raise DeploymentError(
            f"{siem}: deployment returned "
            f"HTTP {status}: "
            f"{body[:2000]}"
        )

    return {
        "status": "success",
        "http_status": status,
        "message": body[:2000],
    }


# ============================================================================
# Manifest update
# ============================================================================

def update_manifest(
    path,
    siem,
    result,
):
    try:

        data = json.loads(
            path.read_text(
                encoding="utf-8"
            )
        )

    except json.JSONDecodeError as exc:

        raise DeploymentError(
            f"Invalid manifest {path}: {exc}"
        ) from exc

    data.setdefault(
        "deployment",
        {}
    )[siem] = result

    path.write_text(
        json.dumps(
            data,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )


# ============================================================================
# Find latest manifest
# ============================================================================

def find_manifest(
    lookup_id,
):
    """
    Expected:

        generated/manifests/
            LKP-001/
                v1.json
                v2.json
                v3.json

    The highest version is returned.
    """

    root = (
        MANIFEST_ROOT
        / lookup_id
    )

    candidates = []

    if root.exists():

        for path in root.glob(
            "v*.json"
        ):

            match = re.fullmatch(
                r"v(\d+)\.json",
                path.name,
            )

            if match:

                candidates.append(
                    (
                        int(
                            match.group(1)
                        ),
                        path,
                    )
                )

    if not candidates:

        raise DeploymentError(
            f"{lookup_id}: "
            f"generation manifest not found"
        )

    return max(
        candidates,
        key=lambda item: item[0],
    )[1]


# ============================================================================
# Main
# ============================================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Deploy generated SIEM lookup "
            "targets using REST APIs."
        )
    )

    parser.add_argument(
        "--lookup-id",
        action="append",
        required=True,
        help=(
            "Lookup ID to deploy. "
            "Can be specified multiple times."
        ),
    )

    args = parser.parse_args()

    # ------------------------------------------------------------------------
    # Load metadata
    # ------------------------------------------------------------------------

    metadata = load_yaml(
        METADATA_FILE
    )

    # ------------------------------------------------------------------------
    # Load deployment configuration
    # ------------------------------------------------------------------------

    deployment = expand(
        load_yaml(
            DEPLOYMENT_FILE
        )
    )

    # ------------------------------------------------------------------------
    # Index lookups by ID
    # ------------------------------------------------------------------------

    by_id = {
        lookup.get("lookup_id"):
            lookup
        for lookup in metadata.get(
            "lookups",
            [],
        )
        if lookup.get("lookup_id")
    }

    failures = []

    # ------------------------------------------------------------------------
    # Process lookup IDs
    # ------------------------------------------------------------------------

    for lookup_id in dict.fromkeys(
        args.lookup_id
    ):

        lookup = by_id.get(
            lookup_id
        )

        if not lookup:

            failures.append(
                f"{lookup_id}: "
                f"not found in metadata"
            )

            continue

        # --------------------------------------------------------------------
        # Find latest generation manifest
        # --------------------------------------------------------------------

        try:

            manifest_path = find_manifest(
                lookup_id
            )

            manifest = json.loads(
                manifest_path.read_text(
                    encoding="utf-8"
                )
            )

        except Exception as exc:

            failures.append(
                f"{lookup_id}: {exc}"
            )

            continue

        # --------------------------------------------------------------------
        # Process SIEMs
        # --------------------------------------------------------------------

        for siem in SUPPORTED_SIEMS:

            target = (
                lookup.get(
                    "targets"
                ) or {}
            ).get(siem) or {}

            # Target is disabled in metadata.
            if not target.get(
                "enabled",
                False,
            ):
                continue

            target_info = (
                manifest.get(
                    "targets",
                    {}
                ).get(siem)
            )

            if not target_info:

                failures.append(
                    f"{lookup_id}/{siem}: "
                    f"target missing from manifest"
                )

                continue

            try:

                # ------------------------------------------------------------
                # Load generated target file
                # ------------------------------------------------------------

                target_path = Path(
                    target_info["path"]
                )

                rows = load_rows(
                    target_path
                )

                # ------------------------------------------------------------
                # Get SIEM lookup name
                # ------------------------------------------------------------

                lookup_name = target_info[
                    "lookup_name"
                ]

                # ------------------------------------------------------------
                # Deploy
                # ------------------------------------------------------------

                result = deploy_one(
                    siem,
                    deployment.get(
                        siem
                    ) or {},
                    lookup_name,
                    rows,
                )

                # ------------------------------------------------------------
                # Update manifest
                # ------------------------------------------------------------

                update_manifest(
                    manifest_path,
                    siem,
                    result,
                )

                print(
                    f"{lookup_id}/{siem}: "
                    f"{result['status']}"
                )

            except Exception as exc:

                result = {
                    "status": "failed",
                    "http_status": None,
                    "message": str(exc),
                }

                try:

                    update_manifest(
                        manifest_path,
                        siem,
                        result,
                    )

                except Exception as manifest_exc:

                    print(
                        f"{lookup_id}/{siem}: "
                        f"WARNING - unable to update "
                        f"manifest: "
                        f"{manifest_exc}"
                    )

                failures.append(
                    f"{lookup_id}/{siem}: "
                    f"{exc}"
                )

                print(
                    f"{lookup_id}/{siem}: "
                    f"FAILED - {exc}"
                )

    # ------------------------------------------------------------------------
    # Final result
    # ------------------------------------------------------------------------

    if failures:

        print(
            "\nDeployment failed:"
        )

        for failure in failures:
            print(
                f"- {failure}"
            )

        raise SystemExit(1)

    print(
        "\nDeployment completed successfully."
    )


# ============================================================================
# Entry point
# ============================================================================

if __name__ == "__main__":
    main()