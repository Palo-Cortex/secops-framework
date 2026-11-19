"""The tenant credentials a repo tool uses: the environment first, a file only to fill gaps.

Run a tool through povkit so its key comes from the OS credential store and exists
only in that one process:

    povkit exec deathstar -- python3 tools/check_contribution.py --input Packs/<pack>

In CI the same variables come from the workflow's secrets. A credentials file is
still read when one is named (or `.env` exists), but only for a variable the
environment does not already set, so a file can never point a tool at a different
tenant from the one povkit or CI chose.
"""
import os

KEYS = ("DEMISTO_BASE_URL", "DEMISTO_API_KEY", "XSIAM_AUTH_ID")


def _read_file(path):
    values = {}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                values[k.strip()] = v.strip().strip('"').strip("'")
    return values


def tenant_credentials(env_file=None, required=True):
    """{DEMISTO_BASE_URL, DEMISTO_API_KEY, XSIAM_AUTH_ID} from the environment, then the file.

    env_file: a credentials file to fill what the environment lacks. With None,
    `.env` at the repo root is used if it exists.
    required: raise SystemExit naming what is missing, rather than return a gap.
    """
    creds = {k: os.environ[k] for k in KEYS if os.environ.get(k)}
    if len(creds) < len(KEYS):
        path = env_file or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env")
        if os.path.exists(path):
            for k, v in _read_file(path).items():
                if k in KEYS and v:
                    creds.setdefault(k, v)
    missing = [k for k in KEYS if not creds.get(k)]
    if missing and required:
        raise SystemExit("missing tenant credentials: {}. Run the tool through povkit: "
                         "povkit exec <tenant> -- python3 tools/<tool>.py ...".format(", ".join(missing)))
    return creds
