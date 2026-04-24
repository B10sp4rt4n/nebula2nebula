import argparse
import base64
import csv
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

import requests
from dotenv import load_dotenv


load_dotenv()


TOKEN_URL = os.getenv("THREATDOWN_TOKEN_URL", "https://api.threatdown.com/oauth2/token")
API_BASE_URL = os.getenv("THREATDOWN_API_BASE_URL", "https://api.threatdown.com")
DEFAULT_SCOPE = os.getenv("THREATDOWN_SCOPE", "read write execute")
DEFAULT_ENDPOINTS_PATH = os.getenv("THREATDOWN_ENDPOINTS_PATH", "/nebula/v1/endpoints")


def build_basic_auth_header(client_id: str, client_secret: str) -> str:
    raw = f"{client_id}:{client_secret}".encode("ascii")
    encoded = base64.b64encode(raw).decode("ascii")
    return f"Basic {encoded}"


def get_access_token(client_id: str, client_secret: str, scope: str) -> str:
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": build_basic_auth_header(client_id, client_secret),
    }
    data = {
        "grant_type": "client_credentials",
        "scope": scope,
    }
    response = requests.post(TOKEN_URL, headers=headers, data=data, timeout=30)
    response.raise_for_status()
    payload = response.json()
    token = payload.get("access_token")
    if not token:
        raise RuntimeError("Token response did not include access_token")
    return token


def _extract_items(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]

    if isinstance(payload, dict):
        for key in ("items", "results", "data", "endpoints"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]

    return []


def _extract_next(payload: Any, response: requests.Response) -> Optional[str]:
    link_header = response.headers.get("Link", "")
    if link_header:
        for part in link_header.split(","):
            segment = part.strip()
            if 'rel="next"' in segment and segment.startswith("<") and ">" in segment:
                return segment[1 : segment.index(">")]

    if isinstance(payload, dict):
        links = payload.get("links")
        if isinstance(links, dict) and isinstance(links.get("next"), str):
            return links["next"]

        for key in ("next", "next_url", "next_page", "nextPage"):
            if isinstance(payload.get(key), str):
                return payload[key]

    return None


def fetch_all_endpoints(token: str, endpoints_path: str, page_size: int, max_pages: int) -> List[Dict[str, Any]]:
    all_items: List[Dict[str, Any]] = []
    path = endpoints_path.strip() or DEFAULT_ENDPOINTS_PATH
    if not path.startswith("/"):
        path = f"/{path}"

    url = f"{API_BASE_URL}{path}"
    params: Dict[str, Any] = {"limit": page_size}

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }

    page = 0
    while True:
        page += 1
        response = requests.get(url, headers=headers, params=params, timeout=30)
        if response.status_code == 404 and params:
            response = requests.get(url, headers=headers, timeout=30)
            params = {}
        response.raise_for_status()

        payload: Any
        if "application/json" in response.headers.get("Content-Type", "").lower():
            payload = response.json()
        else:
            raise RuntimeError(f"Unexpected content type: {response.headers.get('Content-Type', '')}")

        items = _extract_items(payload)
        all_items.extend(items)

        next_url = _extract_next(payload, response)
        if not next_url:
            break

        if max_pages and page >= max_pages:
            break

        if next_url.startswith("http://") or next_url.startswith("https://"):
            url = next_url
            params = {}
        else:
            url = f"{API_BASE_URL}{next_url}"
            params = {}

    return all_items


def print_table(endpoints: List[Dict[str, Any]]) -> None:
    print("id\tname\tonline\tlast_seen_at\tos_platform")
    for ep in endpoints:
        print(
            "\t".join(
                [
                    str(ep.get("id", "")),
                    str(ep.get("name", "")),
                    str(ep.get("online", "")),
                    str(ep.get("last_seen_at", "")),
                    str(ep.get("os_platform", "")),
                ]
            )
        )


def write_csv(endpoints: List[Dict[str, Any]], csv_file: Optional[str]) -> None:
    fieldnames = ["id", "name", "online", "last_seen_at", "os_platform"]
    output = sys.stdout
    should_close = False

    if csv_file:
        output = open(csv_file, "w", newline="", encoding="utf-8")
        should_close = True

    try:
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for ep in endpoints:
            writer.writerow(
                {
                    "id": ep.get("id", ""),
                    "name": ep.get("name", ""),
                    "online": ep.get("online", ""),
                    "last_seen_at": ep.get("last_seen_at", ""),
                    "os_platform": ep.get("os_platform", ""),
                }
            )
    finally:
        if should_close:
            output.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="List ThreatDown endpoints from console")
    parser.add_argument("--client-id", default=os.getenv("THREATDOWN_CLIENT_ID", ""))
    parser.add_argument("--client-secret", default=os.getenv("THREATDOWN_CLIENT_SECRET", ""))
    parser.add_argument("--scope", default=DEFAULT_SCOPE)
    parser.add_argument("--token", default=os.getenv("THREATDOWN_ACCESS_TOKEN", ""))
    parser.add_argument("--endpoints-path", default=DEFAULT_ENDPOINTS_PATH)
    parser.add_argument("--page-size", type=int, default=200)
    parser.add_argument("--max-pages", type=int, default=0, help="0 means no explicit max")
    parser.add_argument("--output", choices=["table", "json", "csv"], default="table")
    parser.add_argument("--csv-file", default="", help="Output CSV path (default: stdout)")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    token = args.token.strip()
    if not token:
        if not args.client_id.strip() or not args.client_secret.strip():
            print(
                "Error: provide --token or set --client-id and --client-secret "
                "(or THREATDOWN_CLIENT_ID/THREATDOWN_CLIENT_SECRET)",
                file=sys.stderr,
            )
            return 2

        try:
            token = get_access_token(args.client_id.strip(), args.client_secret.strip(), args.scope.strip())
        except Exception as exc:
            print(f"Error obtaining token: {exc}", file=sys.stderr)
            return 1

    try:
        endpoints = fetch_all_endpoints(token, args.endpoints_path, args.page_size, args.max_pages)
    except Exception as exc:
        print(f"Error listing endpoints: {exc}", file=sys.stderr)
        return 1

    if args.output == "json":
        print(json.dumps(endpoints, indent=2))
    elif args.output == "csv":
        write_csv(endpoints, args.csv_file.strip() or None)
        if args.csv_file.strip():
            print(f"CSV written to: {args.csv_file.strip()}", file=sys.stderr)
        print(f"Total endpoints: {len(endpoints)}", file=sys.stderr)
    else:
        print_table(endpoints)
        print(f"\nTotal endpoints: {len(endpoints)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
