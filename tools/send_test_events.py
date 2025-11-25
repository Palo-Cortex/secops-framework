import os
import json
import argparse
import requests
from dotenv import load_dotenv
from datetime import datetime, timezone

def load_env(env_path: str) -> None:
    if not os.path.isfile(env_path):
        raise FileNotFoundError(f".env file not found at: {env_path}")
    load_dotenv(env_path)
    for var in ("API_URL", "API_KEY"):
        if os.getenv(var) is None:
            raise EnvironmentError(f"Missing {var} in {env_path}")

def read_events(path: str):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, list) else [data]

def set_timestamps(events):
    now_iso = datetime.now(timezone.utc).isoformat()
    for ev in events:
        ev["_time"] = now_iso
        ev["_insert_time"] = now_iso
    print(f"[*] Updated _time/_insert_time on {len(events)} event(s) → {now_iso}")
    return events

def send_events(events, api_url: str, api_key: str):
    # One JSON object per line, as per HTTP Log Collector doc
    body = "\n".join(json.dumps(ev) for ev in events)

    headers = {
        # Doc example uses bare api_key, not Bearer:
        # "Authorization": api_key,
        "Authorization": api_key,
        "Content-Type": "application/json",
    }

    print(f"[*] Sending {len(events)} events to {api_url}")
    resp = requests.post(api_url, headers=headers, data=body, timeout=30)
    print(f"[+] HTTP {resp.status_code}")
    try:
        print(resp.text)
    except Exception:
        pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", required=True, help="JSON file with event(s)")
    parser.add_argument("--env", default=".env-brumxdr-crowdstrike")
    args = parser.parse_args()

    # resolve env path from tools/
    env_path = args.env
    if not os.path.isabs(env_path):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        repo_root = os.path.dirname(script_dir)
        env_path = os.path.join(repo_root, env_path)

    load_env(env_path)
    api_url = os.getenv("API_URL")
    api_key = os.getenv("API_KEY")

    events = read_events(args.file)
    events = set_timestamps(events)
    send_events(events, api_url, api_key)


if __name__ == "__main__":
    main()
