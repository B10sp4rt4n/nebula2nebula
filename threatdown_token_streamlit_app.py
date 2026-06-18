import base64
import csv
import json
import os
import sqlite3
from io import BytesIO
from io import StringIO
from typing import Optional, Tuple

import pandas as pd
import requests
import streamlit as st
from dotenv import load_dotenv


load_dotenv()


# =============================================================================
# MULTI-MIGRATION SUPPORT
# =============================================================================
def load_available_migrations() -> dict:
    """
    Detecta todas las migraciones configuradas en el .env.
    Retorna un dict: {migration_id: {name, source_config, target_config}}
    """
    migrations = {}
    env_keys = os.environ.keys()
    
    # Buscar todas las migraciones (MIGRATION_1_NAME, MIGRATION_2_NAME, etc.)
    for key in env_keys:
        if key.startswith("MIGRATION_") and key.endswith("_NAME"):
            # Extraer el número de migración
            parts = key.split("_")
            if len(parts) >= 3:
                try:
                    migration_num = int(parts[1])
                    migration_name = os.getenv(key, f"Migration {migration_num}")
                    
                    prefix = f"MIGRATION_{migration_num}_"
                    
                    # Cargar configuración SOURCE
                    source_config = {
                        "api_base_url": os.getenv(f"{prefix}SOURCE_API_BASE_URL", "https://api.malwarebytes.com"),
                        "token_url": os.getenv(f"{prefix}SOURCE_TOKEN_URL", "https://api.malwarebytes.com/oauth2/token"),
                        "client_id": os.getenv(f"{prefix}SOURCE_CLIENT_ID", ""),
                        "client_secret": os.getenv(f"{prefix}SOURCE_CLIENT_SECRET", ""),
                        "account_id": os.getenv(f"{prefix}SOURCE_ACCOUNT_ID", ""),
                        "scope": os.getenv(f"{prefix}SOURCE_SCOPE", "read write execute"),
                        "endpoints_path": os.getenv(f"{prefix}SOURCE_ENDPOINTS_PATH", "/nebula/v1/endpoints"),
                        "endpoints_method": os.getenv(f"{prefix}SOURCE_ENDPOINTS_METHOD", "GET"),
                    }
                    
                    # Cargar configuración TARGET
                    target_config = {
                        "api_base_url": os.getenv(f"{prefix}TARGET_API_BASE_URL", "https://api.malwarebytes.com"),
                        "token_url": os.getenv(f"{prefix}TARGET_TOKEN_URL", "https://api.malwarebytes.com/oauth2/token"),
                        "client_id": os.getenv(f"{prefix}TARGET_CLIENT_ID", ""),
                        "client_secret": os.getenv(f"{prefix}TARGET_CLIENT_SECRET", ""),
                        "account_id": os.getenv(f"{prefix}TARGET_ACCOUNT_ID", ""),
                        "scope": os.getenv(f"{prefix}TARGET_SCOPE", "read write execute"),
                        "move_endpoint_path": os.getenv(f"{prefix}TARGET_MOVE_ENDPOINT_PATH", "/nebula/v1/jobs"),
                    }
                    
                    migrations[migration_num] = {
                        "name": migration_name,
                        "source": source_config,
                        "target": target_config,
                    }
                except ValueError:
                    pass
    
    return migrations


def get_active_migration_config() -> Tuple[int, dict]:
    """Retorna (migration_id, config) de la migración activa"""
    migrations = load_available_migrations()
    
    if not migrations:
        return None, {}
    
    # Obtener migración activa del .env o usar la primera disponible
    active_id = int(os.getenv("ACTIVE_MIGRATION", min(migrations.keys())))
    
    if active_id in migrations:
        return active_id, migrations[active_id]
    else:
        # Fallback a la primera disponible
        active_id = min(migrations.keys())
        return active_id, migrations[active_id]


# Cargar configuración de migraciones disponibles
_available_migrations = load_available_migrations()
_active_migration_id, _active_migration = get_active_migration_config()

# Si hay múltiples migraciones, ofrecer selector en sidebar
if len(_available_migrations) > 1:
    if "selected_migration" not in st.session_state:
        st.session_state.selected_migration = _active_migration_id
else:
    st.session_state.selected_migration = _active_migration_id if _active_migration_id else 1


TOKEN_URL = os.getenv("SOURCE_TOKEN_URL", "https://api.threatdown.com/oauth2/token")
API_BASE_URL = os.getenv("SOURCE_API_BASE_URL", "https://api.threatdown.com")
DEFAULT_SCOPE = "read write execute"
DEFAULT_ENDPOINTS_PATH = os.getenv(
    "THREATDOWN_ENDPOINTS_PATH",
    os.getenv("SOURCE_ENDPOINTS_PATH", "/nebula/v1/endpoints"),
)
DEFAULT_SOURCE_ACCOUNT_ID = os.getenv("SOURCE_ACCOUNT_ID", "")
DEFAULT_TARGET_API_BASE_URL = os.getenv("TARGET_API_BASE_URL", "https://api.threatdown.com")
DEFAULT_TARGET_TOKEN_URL = os.getenv("TARGET_TOKEN_URL", "https://api.threatdown.com/oauth2/token")
DEFAULT_TARGET_CLIENT_ID = os.getenv("TARGET_CLIENT_ID", "")
DEFAULT_TARGET_CLIENT_SECRET = os.getenv("TARGET_CLIENT_SECRET", "")
DEFAULT_TARGET_ACCOUNT_ID = os.getenv("TARGET_ACCOUNT_ID", "")
DEFAULT_TARGET_SCOPE = os.getenv("TARGET_SCOPE", "read write execute")
DEFAULT_TARGET_MOVE_PATH = os.getenv("TARGET_MOVE_ENDPOINT_PATH", "/nebula/v1/jobs")
DEFAULT_MIGRATION_COMMAND = os.getenv("MIGRATION_COMMAND", "command.engine.changeaccounttoken")
DEFAULT_DESTINATION_ACCOUNT_TOKEN = os.getenv("DESTINATION_ACCOUNT_TOKEN", "")
DEFAULT_MOVE_CANDIDATE_PATHS = [
    "/nebula/v1/jobs",
    "/v1/jobs",
    "/nebula/v1/endpoints/move",
]
DEFAULT_CANDIDATE_PATHS = [
    "/nebula/v1/endpoints",
    "/nebula/v1/endpoint",
    "/nebula/v1/devices",
    "/nebula/v1/hosts",
    "/v1/endpoints",
]
DEFAULT_ONEVIEW_API_BASE_URL = os.getenv("ONEVIEW_API_BASE_URL", "https://api.malwarebytes.com")
DEFAULT_ONEVIEW_TOKEN_URL = os.getenv(
    "ONEVIEW_TOKEN_URL",
    "https://api.malwarebytes.com/oneview/oauth2/token",
)
DEFAULT_ONEVIEW_SCOPE = os.getenv("ONEVIEW_SCOPE", "read write execute")
DEFAULT_EDRON_CLIENT_ID = os.getenv("TD_CLIENT_ID_2", os.getenv("TD_CLIENT_ID", ""))
DEFAULT_EDRON_CLIENT_SECRET = os.getenv("TD_CLIENT_SECRET_2", os.getenv("TD_CLIENT_SECRET", ""))


st.set_page_config(page_title="ThreatDown Token Viewer", page_icon="🔐", layout="centered")


def build_basic_auth_header(client_id: str, client_secret: str) -> str:
    raw = f"{client_id}:{client_secret}".encode("ascii")
    encoded = base64.b64encode(raw).decode("ascii")
    return f"Basic {encoded}"


@st.cache_data(show_spinner=False, ttl=300)
def get_token(client_id: str, client_secret: str, scope: str, token_url: str = TOKEN_URL) -> Tuple[Optional[str], dict]:
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": build_basic_auth_header(client_id, client_secret),
    }

    data = {
        "grant_type": "client_credentials",
        "scope": scope,
    }

    try:
        response = requests.post(token_url, headers=headers, data=data, timeout=30)
        content_type = response.headers.get("Content-Type", "")

        if "application/json" in content_type.lower():
            payload = response.json()
        else:
            payload = {"raw_response": response.text}

        response.raise_for_status()
        return payload.get("access_token"), payload
    except requests.RequestException as exc:
        detail = {"error": str(exc)}
        if getattr(exc, "response", None) is not None:
            try:
                detail["response_json"] = exc.response.json()
            except Exception:
                detail["response_text"] = exc.response.text
        return None, detail


def get_endpoint_by_id(access_token: str, endpoint_id: str) -> Tuple[Optional[dict], dict]:
    url = f"{API_BASE_URL}/nebula/v1/endpoints/{endpoint_id}"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }

    try:
        response = requests.get(url, headers=headers, timeout=30)
        content_type = response.headers.get("Content-Type", "")

        if "application/json" in content_type.lower():
            payload = response.json()
        else:
            payload = {"raw_response": response.text}

        response.raise_for_status()
        return payload, payload
    except requests.RequestException as exc:
        detail = {"error": str(exc), "url": url}
        if getattr(exc, "response", None) is not None:
            try:
                detail["response_json"] = exc.response.json()
            except Exception:
                detail["response_text"] = exc.response.text
        return None, detail


@st.cache_data(show_spinner=False, ttl=300)
def get_nebula_account_context(
    client_id: str,
    client_secret: str,
    scope: str,
    token_url: str,
    api_base_url: str,
    account_id: str = "",
) -> Tuple[Optional[dict], dict]:
    token, token_detail = get_token(client_id, client_secret, scope, token_url=token_url)
    if not token:
        return None, {"stage": "token", **token_detail}

    url = f"{(api_base_url or DEFAULT_TARGET_API_BASE_URL).strip().rstrip('/')}/nebula/v1/account"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    if account_id.strip():
        headers["accountid"] = account_id.strip()

    try:
        response = requests.get(url, headers=headers, timeout=30)
        content_type = response.headers.get("Content-Type", "")
        if "application/json" in content_type.lower():
            payload = response.json()
        else:
            payload = {"raw_response": response.text}

        response.raise_for_status()
        if isinstance(payload, dict):
            return payload, {"url": url, "account_id": payload.get("id", account_id)}
        return None, {"url": url, "error": "Respuesta inesperada de /nebula/v1/account"}
    except requests.RequestException as exc:
        detail = {"stage": "account", "error": str(exc), "url": url}
        if getattr(exc, "response", None) is not None:
            try:
                detail["response_json"] = exc.response.json()
            except Exception:
                detail["response_text"] = exc.response.text
        return None, detail


def build_console_catalog() -> list:
    consoles = []

    source_console = {
        "key": "source_nebula",
        "label": os.getenv("SOURCE_CONSOLE_NAME", "SOURCE"),
        "kind": "Nebula",
        "api_base_url": st.session_state.get("source_api_base_url", os.getenv("SOURCE_API_BASE_URL", API_BASE_URL)).strip(),
        "token_url": st.session_state.get("source_token_url", os.getenv("SOURCE_TOKEN_URL", TOKEN_URL)).strip(),
        "client_id": os.getenv("THREATDOWN_CLIENT_ID", os.getenv("SOURCE_CLIENT_ID", "")).strip(),
        "client_secret": os.getenv("THREATDOWN_CLIENT_SECRET", os.getenv("SOURCE_CLIENT_SECRET", "")).strip(),
        "account_id": os.getenv("SOURCE_ACCOUNT_ID", "").strip(),
        "scope": os.getenv("SOURCE_SCOPE", DEFAULT_SCOPE).strip() or DEFAULT_SCOPE,
        "account_token": os.getenv("SOURCE_ACCOUNT_TOKEN", "").strip(),
    }
    if any(source_console[field] for field in ("client_id", "account_id", "api_base_url")):
        consoles.append(source_console)

    target_console = {
        "key": "target_nebula",
        "label": os.getenv("TARGET_CONSOLE_NAME", "TARGET"),
        "kind": "Nebula",
        "api_base_url": st.session_state.get("target_api_base_url", os.getenv("TARGET_API_BASE_URL", DEFAULT_TARGET_API_BASE_URL)).strip(),
        "token_url": st.session_state.get("target_token_url", os.getenv("TARGET_TOKEN_URL", DEFAULT_TARGET_TOKEN_URL)).strip(),
        "client_id": st.session_state.get("target_client_id", os.getenv("TARGET_CLIENT_ID", "")).strip(),
        "client_secret": st.session_state.get("target_client_secret", os.getenv("TARGET_CLIENT_SECRET", "")).strip(),
        "account_id": os.getenv("TARGET_ACCOUNT_ID", "").strip(),
        "scope": st.session_state.get("target_scope", os.getenv("TARGET_SCOPE", DEFAULT_TARGET_SCOPE)).strip() or DEFAULT_TARGET_SCOPE,
        "account_token": st.session_state.get(
            "target_destination_account_token",
            os.getenv("TARGET_ACCOUNT_TOKEN", DEFAULT_DESTINATION_ACCOUNT_TOKEN),
        ).strip(),
        "move_path": os.getenv("TARGET_MOVE_ENDPOINT_PATH", DEFAULT_TARGET_MOVE_PATH).strip() or DEFAULT_TARGET_MOVE_PATH,
    }
    if any(target_console[field] for field in ("client_id", "account_id", "api_base_url")):
        consoles.append(target_console)

    target_console_2 = {
        "key": "target_nebula_2",
        "label": os.getenv("TARGET_CONSOLE_NAME_2", "TARGET 2"),
        "kind": "Nebula",
        "api_base_url": os.getenv("TARGET_API_BASE_URL_2", os.getenv("TARGET_API_BASE_URL", DEFAULT_TARGET_API_BASE_URL)).strip(),
        "token_url": os.getenv("TARGET_TOKEN_URL_2", os.getenv("TARGET_TOKEN_URL", DEFAULT_TARGET_TOKEN_URL)).strip(),
        "client_id": os.getenv("TARGET_CLIENT_ID_2", "").strip(),
        "client_secret": os.getenv("TARGET_CLIENT_SECRET_2", "").strip(),
        "account_id": os.getenv("TARGET_ACCOUNT_ID_2", "").strip(),
        "scope": os.getenv("TARGET_SCOPE_2", os.getenv("TARGET_SCOPE", DEFAULT_TARGET_SCOPE)).strip() or DEFAULT_TARGET_SCOPE,
        "account_token": os.getenv("TARGET_ACCOUNT_TOKEN_2", "").strip(),
        "move_path": os.getenv("TARGET_MOVE_ENDPOINT_PATH_2", os.getenv("TARGET_MOVE_ENDPOINT_PATH", DEFAULT_TARGET_MOVE_PATH)).strip() or DEFAULT_TARGET_MOVE_PATH,
    }
    if any(target_console_2[field] for field in ("client_id", "account_id", "api_base_url")):
        consoles.append(target_console_2)

    edron_oneview_console = {
        "key": "edron_oneview",
        "label": os.getenv("EDRON_ONEVIEW_CONSOLE_NAME", "EDRON OneView"),
        "kind": "OneView",
        "api_base_url": st.session_state.get("edron_api_base_url", os.getenv("ONEVIEW_API_BASE_URL", DEFAULT_ONEVIEW_API_BASE_URL)).strip(),
        "token_url": os.getenv("ONEVIEW_TOKEN_URL", DEFAULT_ONEVIEW_TOKEN_URL).strip(),
        "client_id": os.getenv("TD_CLIENT_ID_2", os.getenv("TD_CLIENT_ID", "")).strip(),
        "client_secret": os.getenv("TD_CLIENT_SECRET_2", os.getenv("TD_CLIENT_SECRET", "")).strip(),
        "account_id": "",
        "scope": os.getenv("ONEVIEW_SCOPE", DEFAULT_ONEVIEW_SCOPE).strip() or DEFAULT_ONEVIEW_SCOPE,
        "account_token": "",
    }
    if any(edron_oneview_console[field] for field in ("client_id", "api_base_url")):
        consoles.append(edron_oneview_console)

    # Agregar consolas de migraciones dinámicas (MIGRATION_N_*)
    existing_client_ids = {c.get("client_id") for c in consoles}
    for mid, migration in sorted(_available_migrations.items()):
        migration_name = migration.get("name", f"Migration {mid}")
        src = migration.get("source", {})
        tgt = migration.get("target", {})

        # SOURCE de la migración
        src_cid = src.get("client_id", "").strip()
        if src_cid and src_cid not in existing_client_ids:
            consoles.append({
                "key": f"migration_{mid}_source",
                "label": f"{migration_name} – Origen",
                "kind": "Nebula",
                "api_base_url": src.get("api_base_url", "https://api.malwarebytes.com"),
                "token_url": src.get("token_url", "https://api.malwarebytes.com/oauth2/token"),
                "client_id": src_cid,
                "client_secret": src.get("client_secret", ""),
                "account_id": src.get("account_id", ""),
                "scope": src.get("scope", "read write execute"),
                "account_token": "",
                "endpoints_path": src.get("endpoints_path", "/nebula/v1/endpoints"),
                "endpoints_method": os.getenv(f"MIGRATION_{mid}_SOURCE_ENDPOINTS_METHOD", "GET"),
                "move_path": "/nebula/v1/jobs",
            })
            existing_client_ids.add(src_cid)

        # TARGET de la migración
        tgt_cid = tgt.get("client_id", "").strip()
        if tgt_cid and tgt_cid not in existing_client_ids:
            consoles.append({
                "key": f"migration_{mid}_target",
                "label": f"{migration_name} – Destino",
                "kind": "Nebula",
                "api_base_url": tgt.get("api_base_url", "https://api.malwarebytes.com"),
                "token_url": tgt.get("token_url", "https://api.malwarebytes.com/oauth2/token"),
                "client_id": tgt_cid,
                "client_secret": tgt.get("client_secret", ""),
                "account_id": tgt.get("account_id", ""),
                "scope": tgt.get("scope", "read write execute"),
                "account_token": os.getenv("DESTINATION_ACCOUNT_TOKEN", ""),
                "move_path": tgt.get("move_endpoint_path", "/nebula/v1/jobs"),
            })
            existing_client_ids.add(tgt_cid)

    return consoles


def build_console_catalog_df(consoles: list) -> pd.DataFrame:
    rows = []
    for console in consoles:
        rows.append(
            {
                "Consola": console.get("label", ""),
                "Tipo": console.get("kind", ""),
                "API Base URL": console.get("api_base_url", ""),
                "Token URL": console.get("token_url", ""),
                "Account ID": console.get("account_id", ""),
                "Client ID": "Sí" if console.get("client_id") else "No",
                "Client Secret": "Sí" if console.get("client_secret") else "No",
                "Account Token": "Sí" if console.get("account_token") else "No",
            }
        )
    return pd.DataFrame(rows)


def format_console_option(console: dict) -> str:
    label = console.get("label", "Consola")
    kind = console.get("kind", "")
    account_id = console.get("account_id", "")
    suffix = f" - {account_id}" if account_id else ""
    return f"{label} ({kind}){suffix}"


def extract_items(payload: object) -> list:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]

    if isinstance(payload, dict):
        for key in ("items", "results", "data", "endpoints"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]

    return []


def extract_next(payload: object, response: requests.Response) -> Optional[str]:
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
            value = payload.get(key)
            if isinstance(value, str):
                return value

    return None


def get_all_endpoints(
    access_token: str,
    endpoints_path: str = DEFAULT_ENDPOINTS_PATH,
    api_base_url: str = API_BASE_URL,
    request_method: str = "GET",
    account_id: str = "",
    page_size: int = 200,
    max_pages: int = 0,
) -> Tuple[Optional[list], dict]:
    all_items = []
    path = endpoints_path.strip() or DEFAULT_ENDPOINTS_PATH
    if not path.startswith("/"):
        path = f"/{path}"

    base_url = api_base_url.strip() or API_BASE_URL
    url = f"{base_url}{path}"
    method = request_method.strip().upper() or "GET"
    params = {"limit": page_size} if method == "GET" else {}
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }
    if account_id.strip():
        headers["accountid"] = account_id.strip()

    page = 0
    next_cursor = ""
    try:
        while True:
            page += 1
            if method == "POST":
                body = {"page_size": page_size}
                if next_cursor:
                    body["next_cursor"] = next_cursor
                response = requests.post(url, headers=headers, json=body, timeout=30)
            else:
                response = requests.get(url, headers=headers, params=params, timeout=30)

            # Algunos tenants no aceptan query params en esta ruta; reintenta sin params.
            if method == "GET" and response.status_code == 404 and params:
                response = requests.get(url, headers=headers, timeout=30)
                params = {}

            content_type = response.headers.get("Content-Type", "")

            if "application/json" in content_type.lower():
                payload = response.json()
            else:
                payload = {"raw_response": response.text}

            response.raise_for_status()

            items = extract_items(payload)
            all_items.extend(items)

            if isinstance(payload, dict) and isinstance(payload.get("next_cursor"), str):
                next_cursor = payload.get("next_cursor") or ""

            next_url = extract_next(payload, response)
            if not next_url and not next_cursor:
                break

            if max_pages and page >= max_pages:
                break

            if next_url:
                if next_url.startswith("http://") or next_url.startswith("https://"):
                    url = next_url
                else:
                    url = f"{base_url}{next_url}"
                params = {}

        return all_items, {
            "total": len(all_items),
            "pages_fetched": page,
            "path": path,
            "method": method,
            "accountid": account_id,
            "base_url": base_url,
        }
    except requests.RequestException as exc:
        detail = {
            "error": str(exc),
            "url": url,
            "path": path,
            "method": method,
            "accountid": account_id,
            "base_url": base_url,
            "pages_fetched": page,
            "items_fetched": len(all_items),
        }
        if getattr(exc, "response", None) is not None:
            try:
                detail["response_json"] = exc.response.json()
            except Exception:
                detail["response_text"] = exc.response.text
            if exc.response.status_code == 404:
                detail["hint"] = (
                    "La ruta de listado no existe en este tenant. "
                    "Prueba otra ruta en 'Ruta de listado' (ejemplo: /nebula/v1/endpoints)."
                )
        return None, detail


def endpoints_to_csv(endpoints: list) -> str:
    if not endpoints:
        return ""
    # Usar todas las claves presentes en los datos reales
    all_keys: list = []
    for ep in endpoints:
        for k in ep.keys():
            if k not in all_keys:
                all_keys.append(k)
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=all_keys, extrasaction="ignore")
    writer.writeheader()
    for ep in endpoints:
        writer.writerow({k: ep.get(k, "") for k in all_keys})
    return output.getvalue()


def selected_ids_to_csv(selected_rows: list) -> str:
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=["id", "machine_id", "name"])
    writer.writeheader()
    for row in selected_rows:
        writer.writerow(
            {
                "id": row.get("id", ""),
                "machine_id": row.get("machine_id", ""),
                "name": row.get("name", ""),
            }
        )
    return output.getvalue()


def normalize_text(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def load_cloud_excel(url: str, sheet_name: str = "") -> Tuple[Optional[pd.DataFrame], dict]:
    clean_url = (url or "").strip()
    if not clean_url:
        return None, {"error": "Falta URL del Excel."}

    try:
        response = requests.get(clean_url, timeout=60)
        response.raise_for_status()
        content_type = response.headers.get("Content-Type", "")

        read_kwargs = {}
        if sheet_name.strip():
            read_kwargs["sheet_name"] = sheet_name.strip()

        df = pd.read_excel(BytesIO(response.content), **read_kwargs)
        if isinstance(df, dict):
            first_key = next(iter(df), None)
            if first_key is None:
                return None, {"error": "El Excel no contiene hojas con datos."}
            df = df[first_key]

        if df is None or df.empty:
            return None, {"error": "El Excel no tiene filas para procesar."}

        df = df.rename(columns=lambda c: str(c).strip())
        return df, {
            "rows": int(len(df)),
            "columns": list(df.columns),
            "content_type": content_type,
        }
    except requests.RequestException as exc:
        return None, {"error": f"No se pudo descargar el Excel: {exc}"}
    except Exception as exc:
        return None, {"error": f"No se pudo leer el Excel: {exc}"}


def chunk_rows(rows: list, size: int) -> list:
    if size <= 0:
        size = 1
    return [rows[i : i + size] for i in range(0, len(rows), size)]


def build_match_indexes(selection_rows: list) -> dict:
    indexes = {
        "machine_id": {},
        "id": {},
        "name": {},
    }
    for row in selection_rows:
        for key in indexes.keys():
            v = normalize_text(row.get(key, ""))
            if v:
                indexes[key][v] = row
    return indexes


def match_excel_rows_to_selection(
    excel_df: pd.DataFrame,
    selection_rows: list,
    excel_match_column: str,
    source_match_field: str,
) -> Tuple[list, dict]:
    if excel_match_column not in excel_df.columns:
        return [], {"error": f"La columna '{excel_match_column}' no existe en el Excel."}

    indexes = build_match_indexes(selection_rows)
    if source_match_field not in indexes:
        return [], {"error": f"Campo de origen no válido: {source_match_field}"}

    matched = []
    matched_keys = set()
    for raw in excel_df[excel_match_column].tolist():
        key = normalize_text(raw)
        if not key:
            continue
        row = indexes[source_match_field].get(key)
        if row:
            machine_id = row.get("machine_id", "")
            if machine_id and machine_id not in matched_keys:
                matched.append(row)
                matched_keys.add(machine_id)

    detail = {
        "excel_rows": int(len(excel_df)),
        "matched": len(matched),
        "unmatched": int(len(excel_df) - len(matched)),
        "excel_match_column": excel_match_column,
        "source_match_field": source_match_field,
    }
    return matched, detail


def extract_machine_id(ep: dict) -> str:
    """Extrae machine_id con fallbacks sobre los campos reales del endpoint."""
    machine = ep.get("machine", {}) if isinstance(ep.get("machine"), dict) else {}
    return (
        machine.get("id", "")
        or ep.get("machine_id", "")
        or ep.get("agent_id", "")
        or ep.get("id", "")
    )


def _get_mid_for_log(row: dict, machine_id_field: str) -> str:
    if machine_id_field == "machine.id":
        m = row.get("machine", {})
        return m.get("id", "") if isinstance(m, dict) else ""
    return str(row.get(machine_id_field, "")).strip()


def endpoint_to_selection_row(ep: dict) -> dict:
    # Estructura específica de MLTi: machine_id y host_name en raíz, os_info anidado
    os_info = ep.get("os_info", {}) if isinstance(ep.get("os_info"), dict) else {}
    return {
        "migrar": False,
        "machine_id": ep.get("machine_id", ""),
        "host_name": ep.get("host_name", ""),
        "os_platform": os_info.get("os_platform", ""),
        "machine_ip": ep.get("machine_ip", ""),
        "last_seen": ep.get("at", ""),
        "account_id": ep.get("account_id", ""),
    }


def build_migration_payload_variants(selected_rows: list, destination_account_token: str, command_name: str, machine_id_field: str = "id") -> list:
    def _get_mid(row: dict) -> str:
        if machine_id_field == "machine.id":
            m = row.get("machine", {})
            return m.get("id", "") if isinstance(m, dict) else ""
        return str(row.get(machine_id_field, "")).strip()

    machine_ids = [mid for row in selected_rows if (mid := _get_mid(row))]

    variants = [
        {
            "command": command_name,
            "machine_ids": machine_ids,
            "data": {"account_token": destination_account_token},
        },
    ]

    clean_variants = []
    for payload in variants:
        clean = {k: v for k, v in payload.items() if v not in ("", [], None)}
        if clean not in clean_variants:
            clean_variants.append(clean)
    return clean_variants


def dataframe_to_excel_bytes(df: pd.DataFrame) -> bytes:
    buffer = BytesIO()
    with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="endpoints")
    return buffer.getvalue()


def normalize_oneview_base_url(api_base_url: str) -> str:
    base = (api_base_url or DEFAULT_ONEVIEW_API_BASE_URL).strip().rstrip("/")
    return base[:-8] if base.endswith("/oneview") else base


def get_oneview_sites(access_token: str, api_base_url: str) -> Tuple[Optional[list], dict]:
    base = normalize_oneview_base_url(api_base_url)
    url = f"{base}/oneview/v1/sites"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }

    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        payload = response.json()
        sites = extract_items(payload)
        if not sites and isinstance(payload, dict):
            raw_sites = payload.get("sites")
            if isinstance(raw_sites, list):
                sites = [item for item in raw_sites if isinstance(item, dict)]
        return sites, {"url": url, "count": len(sites)}
    except requests.RequestException as exc:
        detail = {"error": str(exc), "url": url}
        if getattr(exc, "response", None) is not None:
            try:
                detail["response_json"] = exc.response.json()
            except Exception:
                detail["response_text"] = exc.response.text
        return None, detail


def get_oneview_endpoints(
    access_token: str,
    api_base_url: str,
    account_ids: list,
    page_size: int = 200,
    max_pages: int = 0,
) -> Tuple[Optional[list], dict]:
    base = normalize_oneview_base_url(api_base_url)
    url = f"{base}/oneview/v1/endpoints"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    all_items = []
    next_cursor = ""
    page = 0

    try:
        while True:
            page += 1
            body = {
                "account_ids": account_ids,
                "page_size": int(page_size),
            }
            if next_cursor:
                body["next_cursor"] = next_cursor

            response = requests.post(url, headers=headers, json=body, timeout=60)
            response.raise_for_status()

            payload = response.json()
            items = []
            if isinstance(payload, dict):
                raw = payload.get("endpoints")
                if isinstance(raw, list):
                    items = [item for item in raw if isinstance(item, dict)]

            all_items.extend(items)
            next_cursor = payload.get("next_cursor") if isinstance(payload, dict) else ""

            if not next_cursor:
                break
            if max_pages and page >= max_pages:
                break

        return all_items, {
            "url": url,
            "total": len(all_items),
            "pages_fetched": page,
            "account_ids_count": len(account_ids),
        }
    except requests.RequestException as exc:
        detail = {
            "error": str(exc),
            "url": url,
            "pages_fetched": page,
            "items_fetched": len(all_items),
        }
        if getattr(exc, "response", None) is not None:
            try:
                detail["response_json"] = exc.response.json()
            except Exception:
                detail["response_text"] = exc.response.text
        return None, detail


def oneview_endpoint_to_selection_row(ep: dict) -> dict:
    machine = ep.get("machine", {}) if isinstance(ep.get("machine"), dict) else {}
    agent = ep.get("agent", {}) if isinstance(ep.get("agent"), dict) else {}

    display_name = (
        ep.get("display_name")
        or agent.get("host_name")
        or agent.get("fully_qualified_host_name")
        or machine.get("id")
        or ""
    )

    return {
        "migrar": False,
        "display_name": str(display_name),
        "machine_id": str(machine.get("id", "")),
        "account_id": str(machine.get("account_id", "")),
        "connected": bool(ep.get("connected", False)),
        "last_seen_at": str(machine.get("last_day_seen", "")),
        "policy_name": str(machine.get("policy_name", "")),
        "group_name": str(machine.get("group_name", "")),
    }


def init_edron_tracking_table(db_path: str = "oneview_to_nebula.db") -> None:
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS edron_migration_tracking (
            consecutivo INTEGER PRIMARY KEY,
            machine_id TEXT UNIQUE,
            display_name TEXT,
            account_id TEXT,
            policy_name TEXT,
            group_name TEXT,
            last_seen_at TEXT,
            migrado INTEGER DEFAULT 0,
            selected_at TEXT DEFAULT CURRENT_TIMESTAMP,
            migrated_at TEXT
        )
        """
    )
    conn.commit()
    conn.close()


def save_edron_selection_with_consecutivos(selected_rows: list, db_path: str = "oneview_to_nebula.db") -> dict:
    init_edron_tracking_table(db_path)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    max_seq = cur.execute("SELECT COALESCE(MAX(consecutivo), 0) FROM edron_migration_tracking").fetchone()[0]
    inserted = 0
    updated = 0
    skipped = 0

    for row in selected_rows:
        machine_id = str(row.get("machine_id", "")).strip()
        if not machine_id:
            skipped += 1
            continue

        existing = cur.execute(
            "SELECT consecutivo FROM edron_migration_tracking WHERE machine_id = ?",
            (machine_id,),
        ).fetchone()

        values = (
            str(row.get("display_name", "")),
            str(row.get("account_id", "")),
            str(row.get("policy_name", "")),
            str(row.get("group_name", "")),
            str(row.get("last_seen_at", "")),
        )

        if existing:
            cur.execute(
                """
                UPDATE edron_migration_tracking
                SET display_name = ?,
                    account_id = ?,
                    policy_name = ?,
                    group_name = ?,
                    last_seen_at = ?
                WHERE machine_id = ?
                """,
                (*values, machine_id),
            )
            updated += 1
        else:
            max_seq += 1
            cur.execute(
                """
                INSERT INTO edron_migration_tracking (
                    consecutivo, machine_id, display_name, account_id, policy_name, group_name, last_seen_at, migrado
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (max_seq, machine_id, *values),
            )
            inserted += 1

    conn.commit()
    total = cur.execute("SELECT COUNT(*) FROM edron_migration_tracking").fetchone()[0]
    conn.close()

    return {
        "inserted": inserted,
        "updated": updated,
        "skipped": skipped,
        "total_tracking": total,
    }


def load_edron_tracking_df(db_path: str = "oneview_to_nebula.db") -> pd.DataFrame:
    init_edron_tracking_table(db_path)
    conn = sqlite3.connect(db_path)
    query = """
        SELECT
            consecutivo,
            machine_id,
            display_name,
            account_id,
            policy_name,
            group_name,
            last_seen_at,
            migrado,
            selected_at,
            migrated_at
        FROM edron_migration_tracking
        ORDER BY consecutivo
    """
    df = pd.read_sql_query(query, conn)
    conn.close()
    if not df.empty:
        df["migrado"] = df["migrado"].astype(bool)
    return df


def update_edron_tracking_migrado(flags: list, db_path: str = "oneview_to_nebula.db") -> None:
    init_edron_tracking_table(db_path)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    for row in flags:
        consecutivo = int(row.get("consecutivo", 0))
        migrado = bool(row.get("migrado", False))
        cur.execute(
            """
            UPDATE edron_migration_tracking
            SET migrado = ?,
                migrated_at = CASE WHEN ? = 1 THEN CURRENT_TIMESTAMP ELSE NULL END
            WHERE consecutivo = ?
            """,
            (1 if migrado else 0, 1 if migrado else 0, consecutivo),
        )
    conn.commit()
    conn.close()


def run_migration_request(
    access_token: str,
    api_base_url: str,
    jobs_path: str,
    origin_account_id: str,
    payload_variants: list,
) -> Tuple[bool, dict]:
    path = jobs_path.strip() or DEFAULT_TARGET_MOVE_PATH
    if not path.startswith("/"):
        path = f"/{path}"

    base_url = api_base_url.strip() or API_BASE_URL
    url = f"{base_url}{path}"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if origin_account_id.strip():
        headers["accountid"] = origin_account_id.strip()

    attempts = []
    for idx, payload in enumerate(payload_variants, start=1):
        try:
            response = requests.post(url, headers=headers, json=payload, timeout=60)
            content_type = response.headers.get("Content-Type", "")
            if "application/json" in content_type.lower():
                body = response.json()
            else:
                body = response.text

            attempts.append(
                {
                    "attempt": idx,
                    "status_code": response.status_code,
                    "payload": payload,
                    "response": body,
                }
            )

            if 200 <= response.status_code < 300:
                return True, {"url": url, "attempts": attempts, "used_payload": payload}
        except requests.RequestException as exc:
            err = {"attempt": idx, "payload": payload, "error": str(exc)}
            if getattr(exc, "response", None) is not None:
                err["status_code"] = exc.response.status_code
                try:
                    err["response"] = exc.response.json()
                except Exception:
                    err["response"] = exc.response.text
            attempts.append(err)

    return False, {"url": url, "attempts": attempts}


def extract_job_ids_from_batch_results(batch_results: list) -> list:
    job_ids = []
    for batch in batch_results:
        result = batch.get("result", {}) if isinstance(batch, dict) else {}
        attempts = result.get("attempts", []) if isinstance(result, dict) else []
        for attempt in attempts:
            response_body = attempt.get("response") if isinstance(attempt, dict) else None
            if isinstance(response_body, dict):
                jobs = response_body.get("jobs")
                if isinstance(jobs, list):
                    for job in jobs:
                        if isinstance(job, dict):
                            job_id = str(job.get("job_id", "")).strip()
                            if job_id and job_id not in job_ids:
                                job_ids.append(job_id)
    return job_ids


def extract_job_records_from_batch_results(batch_results: list) -> list:
    job_records = []
    seen_pairs = set()
    for batch in batch_results:
        if not isinstance(batch, dict):
            continue
        account_id = str(batch.get("account_id", "")).strip()
        result = batch.get("result", {}) if isinstance(batch.get("result"), dict) else {}
        attempts = result.get("attempts", []) if isinstance(result, dict) else []
        for attempt in attempts:
            response_body = attempt.get("response") if isinstance(attempt, dict) else None
            if isinstance(response_body, dict):
                jobs = response_body.get("jobs")
                if isinstance(jobs, list):
                    for job in jobs:
                        if not isinstance(job, dict):
                            continue
                        job_id = str(job.get("job_id", "")).strip()
                        pair = (job_id, account_id)
                        if job_id and pair not in seen_pairs:
                            seen_pairs.add(pair)
                            job_records.append({"job_id": job_id, "account_id": account_id})
    return job_records


def get_jobs_status_report(
    access_token: str,
    api_base_url: str,
    origin_account_id: str,
    job_ids: list,
) -> Tuple[list, dict]:
    base_url = api_base_url.strip() or API_BASE_URL
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }
    if origin_account_id.strip():
        headers["accountid"] = origin_account_id.strip()

    rows = []
    for job_id in job_ids:
        jid = str(job_id).strip()
        if not jid:
            continue

        url = f"{base_url}/nebula/v1/jobs/{jid}"
        status = "UNKNOWN"
        machine_id = ""
        machine_name = ""
        issued_at = ""
        expires_at = ""
        detail = ""
        status_code = None

        try:
            response = requests.get(url, headers=headers, timeout=30)
            status_code = response.status_code
            content_type = response.headers.get("Content-Type", "")
            if "application/json" in content_type.lower():
                payload = response.json()
            else:
                payload = {"raw_response": response.text}

            if 200 <= response.status_code < 300 and isinstance(payload, dict):
                status = str(
                    payload.get("status")
                    or payload.get("state")
                    or payload.get("job_status")
                    or payload.get("result")
                    or "UNKNOWN"
                ).upper()
                machine_id = str(payload.get("machine_id", ""))
                machine_name = str(payload.get("machine_name", ""))
                issued_at = str(payload.get("issued_at", ""))
                expires_at = str(payload.get("expires_at", ""))
            else:
                status = f"HTTP_{response.status_code}"
                detail = str(payload)[:300]
        except requests.RequestException as exc:
            status = "REQUEST_ERROR"
            detail = str(exc)

        rows.append(
            {
                "job_id": jid,
                "status": status,
                "machine_id": machine_id,
                "machine_name": machine_name,
                "issued_at": issued_at,
                "expires_at": expires_at,
                "http_status": status_code,
                "detail": detail,
            }
        )

    total = len(rows)
    completed = sum(1 for r in rows if r.get("status") == "COMPLETED")
    pending = sum(1 for r in rows if r.get("status") == "PENDING")
    failed = sum(1 for r in rows if r.get("status") in {"FAILED", "ERROR", "CANCELLED"})
    other = max(total - completed - pending - failed, 0)
    completion_pct = round((completed / total) * 100, 2) if total else 0.0

    summary = {
        "total_jobs": total,
        "completed": completed,
        "pending": pending,
        "failed": failed,
        "other": other,
        "completion_pct": completion_pct,
    }
    return rows, summary


def get_jobs_status_report_by_records(
    access_token: str,
    api_base_url: str,
    job_records: list,
) -> Tuple[list, dict]:
    base_url = api_base_url.strip() or API_BASE_URL

    rows = []
    for record in job_records:
        if not isinstance(record, dict):
            continue

        jid = str(record.get("job_id", "")).strip()
        account_id = str(record.get("account_id", "")).strip()
        if not jid:
            continue

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }
        if account_id:
            headers["accountid"] = account_id

        url = f"{base_url}/nebula/v1/jobs/{jid}"
        status = "UNKNOWN"
        machine_id = ""
        machine_name = ""
        issued_at = ""
        expires_at = ""
        detail = ""
        status_code = None

        try:
            response = requests.get(url, headers=headers, timeout=30)
            status_code = response.status_code
            content_type = response.headers.get("Content-Type", "")
            if "application/json" in content_type.lower():
                payload = response.json()
            else:
                payload = {"raw_response": response.text}

            if 200 <= response.status_code < 300 and isinstance(payload, dict):
                status = str(
                    payload.get("status")
                    or payload.get("state")
                    or payload.get("job_status")
                    or payload.get("result")
                    or "UNKNOWN"
                ).upper()
                machine_id = str(payload.get("machine_id", ""))
                machine_name = str(payload.get("machine_name", ""))
                issued_at = str(payload.get("issued_at", ""))
                expires_at = str(payload.get("expires_at", ""))
            else:
                status = f"HTTP_{response.status_code}"
                detail = str(payload)[:300]
        except requests.RequestException as exc:
            status = "REQUEST_ERROR"
            detail = str(exc)

        rows.append(
            {
                "job_id": jid,
                "account_id": account_id,
                "status": status,
                "machine_id": machine_id,
                "machine_name": machine_name,
                "issued_at": issued_at,
                "expires_at": expires_at,
                "http_status": status_code,
                "detail": detail,
            }
        )

    total = len(rows)
    completed = sum(1 for r in rows if r.get("status") == "COMPLETED")
    pending = sum(1 for r in rows if r.get("status") == "PENDING")
    failed = sum(1 for r in rows if r.get("status") in {"FAILED", "ERROR", "CANCELLED"})
    other = max(total - completed - pending - failed, 0)
    completion_pct = round((completed / total) * 100, 2) if total else 0.0

    summary = {
        "total_jobs": total,
        "completed": completed,
        "pending": pending,
        "failed": failed,
        "other": other,
        "completion_pct": completion_pct,
    }
    return rows, summary


def probe_move_paths(
    access_token: str,
    api_base_url: str,
    candidate_paths_text: str,
    accountid_header: str,
) -> list:
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    if accountid_header.strip():
        headers["accountid"] = accountid_header.strip()

    base_url = api_base_url.strip() or API_BASE_URL
    raw_paths = [line.strip() for line in candidate_paths_text.splitlines() if line.strip()]
    unique_paths = []
    for p in raw_paths:
        if p not in unique_paths:
            unique_paths.append(p)

    results = []
    for path in unique_paths:
        final_path = path if path.startswith("/") else f"/{path}"
        url = f"{base_url}{final_path}"
        status = None
        exists = False
        preview = ""
        error_text = ""
        try:
            response = requests.post(url, headers=headers, json={}, timeout=20)
            status = response.status_code
            # Para discovery, una ruta valida puede responder 400/401/403; 404 indica ruta inexistente.
            exists = status != 404
            content_type = response.headers.get("Content-Type", "")
            if "application/json" in content_type.lower():
                try:
                    preview = str(response.json())[:300]
                except Exception:
                    preview = response.text[:300]
            else:
                preview = response.text[:300]
        except requests.RequestException as exc:
            error_text = str(exc)
            if getattr(exc, "response", None) is not None:
                status = exc.response.status_code
                exists = status != 404
                try:
                    preview = str(exc.response.json())[:300]
                except Exception:
                    preview = exc.response.text[:300]

        results.append(
            {
                "path": final_path,
                "url": url,
                "status": status,
                "exists_not_404": exists,
                "preview": preview,
                "error": error_text,
            }
        )

    return results


def probe_paths(access_token: str, candidate_paths_text: str, api_base_url: str = API_BASE_URL) -> list:
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
    }

    raw_paths = [line.strip() for line in candidate_paths_text.splitlines() if line.strip()]
    unique_paths = []
    for p in raw_paths:
        if p not in unique_paths:
            unique_paths.append(p)

    results = []
    base_url = api_base_url.strip() or API_BASE_URL

    for path in unique_paths:
        final_path = path if path.startswith("/") else f"/{path}"
        url = f"{base_url}{final_path}"
        status = None
        payload_preview = ""
        error_text = ""

        try:
            response = requests.get(url, headers=headers, timeout=20)
            status = response.status_code
            content_type = response.headers.get("Content-Type", "")
            if "application/json" in content_type.lower():
                try:
                    payload = response.json()
                    payload_preview = str(payload)[:300]
                except Exception:
                    payload_preview = response.text[:300]
            else:
                payload_preview = response.text[:300]
        except requests.RequestException as exc:
            error_text = str(exc)

        results.append(
            {
                "path": final_path,
                "url": url,
                "status": status,
                "ok": bool(status and 200 <= status < 300),
                "preview": payload_preview,
                "error": error_text,
            }
        )

    return results


st.title("Nebula Migration Assistant")
st.caption("Pestana unica para seleccionar endpoints y preparar lote de migracion.")

# =============================================================================
# MULTI-MIGRATION SELECTOR
# =============================================================================
if len(_available_migrations) > 1:
    st.divider()
    col1, col2 = st.columns([3, 1])
    
    with col1:
        migration_options = {
            mid: f"{cfg['name']} (ID: {mid})" 
            for mid, cfg in _available_migrations.items()
        }
        selected_migration = st.selectbox(
            "🔄 Selecciona la migración:",
            options=sorted(migration_options.keys()),
            format_func=lambda x: migration_options[x],
            key="sidebar_migration_selector",
        )
        if selected_migration != st.session_state.selected_migration:
            st.session_state.selected_migration = selected_migration
            st.rerun()
    
    with col2:
        st.metric(
            "Total",
            f"{len(_available_migrations)} migraciones"
        )
    
    st.divider()
    
    # Usar configuración de la migración seleccionada
    current_migration = _available_migrations[st.session_state.selected_migration]
    st.info(f"**Activa:** {current_migration['name']}")
else:
    current_migration = _active_migration if _active_migration else {}
    if current_migration:
        st.info(f"**Migración:** {current_migration['name']}")

console_catalog = build_console_catalog()
console_lookup = {console["key"]: console for console in console_catalog}

# Si hay migraciones MIGRATION_N_* configuradas, filtrar el catálogo a solo
# las consolas de la migración activa para no mezclar con esquema antiguo.
_active_mid = st.session_state.get("selected_migration", 1)
_active_mid_src_key = f"migration_{_active_mid}_source"
_active_mid_tgt_key = f"migration_{_active_mid}_target"
_migration_keys_present = any(k.startswith("migration_") for k in console_lookup)

if _migration_keys_present:
    # Solo mostrar consolas de la migración activa
    all_console_keys = [k for k in console_lookup if k in (_active_mid_src_key, _active_mid_tgt_key)]
    nebula_console_keys = [k for k in all_console_keys if console_lookup[k].get("kind") == "Nebula"]
    oneview_console_keys = [k for k in console_lookup if console_lookup[k].get("kind") == "OneView"]
else:
    all_console_keys = [console["key"] for console in console_catalog]
    nebula_console_keys = [console["key"] for console in console_catalog if console.get("kind") == "Nebula"]
    oneview_console_keys = [console["key"] for console in console_catalog if console.get("kind") == "OneView"]

with st.expander("Consolas configuradas", expanded=False):
    visible_catalog = [console_lookup[k] for k in all_console_keys if k in console_lookup]
    if visible_catalog:
        st.dataframe(build_console_catalog_df(visible_catalog), hide_index=True, use_container_width=True)
    else:
        st.warning("No se detectaron consolas configuradas en el entorno actual.")

    if len(nebula_console_keys) < 2:
        st.warning("Se necesitan al menos dos consolas Nebula configuradas para elegir origen y destino sin repetir.")

# Auto-seleccionar origen/destino según migración activa
if _migration_keys_present and _active_mid_src_key in console_lookup:
    migration_origin_default = _active_mid_src_key
    migration_destination_default = _active_mid_tgt_key if _active_mid_tgt_key in console_lookup else ""
else:
    migration_origin_default = st.session_state.get("migration_origin_console_key", all_console_keys[0] if all_console_keys else "")
    if migration_origin_default not in all_console_keys and all_console_keys:
        migration_origin_default = all_console_keys[0]
    migration_destination_default = st.session_state.get("migration_destination_console_key", "")

migration_destination_candidates = [key for key in nebula_console_keys if key != migration_origin_default]
if migration_destination_default not in migration_destination_candidates and migration_destination_candidates:
    migration_destination_default = migration_destination_candidates[0]

edron_source_default = st.session_state.get("edron_origin_console_key", oneview_console_keys[0] if oneview_console_keys else "")
if edron_source_default not in oneview_console_keys and oneview_console_keys:
    edron_source_default = oneview_console_keys[0]

edron_destination_default = st.session_state.get(
    "edron_destination_console_key",
    nebula_console_keys[0] if nebula_console_keys else "",
)
if edron_destination_default not in nebula_console_keys and nebula_console_keys:
    edron_destination_default = nebula_console_keys[0]

selected_migration_source_console = console_lookup.get(migration_origin_default, {})
selected_migration_destination_console = console_lookup.get(migration_destination_default, {})
selected_edron_source_console = console_lookup.get(edron_source_default, {})
selected_edron_destination_console = console_lookup.get(edron_destination_default, {})

tab_migration, tab_edron = st.tabs(["Migracion", "Edron OneView"])

with tab_migration:
    with st.expander("Recomendación de seguridad", expanded=False):
        st.warning(
            "No pegues secretos reales en código fuente ni los subas a Git. "
            "Lo ideal es usar variables de entorno o un secret manager. "
            "Si ya expusiste un secret, rótalo antes de usar esta app."
        )

    st.subheader("Consolas de la migración")
    if all_console_keys:
        if _migration_keys_present:
            # En modo multi-migración: origen y destino fijos por migración seleccionada
            migration_origin_key = migration_origin_default if migration_origin_default in all_console_keys else (all_console_keys[0] if all_console_keys else "")
            migration_destination_key = migration_destination_default if migration_destination_default in nebula_console_keys else (migration_destination_candidates[0] if migration_destination_candidates else "")
            col_console_1, col_console_2 = st.columns(2)
            col_console_1.info(f"**Origen:** {console_lookup.get(migration_origin_key, {}).get('label', migration_origin_key)}")
            col_console_2.info(f"**Destino:** {console_lookup.get(migration_destination_key, {}).get('label', migration_destination_key)}")
        else:
            col_console_1, col_console_2 = st.columns(2)
            migration_origin_key = col_console_1.selectbox(
                "Consola de origen",
                options=all_console_keys,
                index=all_console_keys.index(migration_origin_default),
                format_func=lambda key: format_console_option(console_lookup[key]),
                key="migration_origin_console_key",
            )
            migration_destination_options = [key for key in nebula_console_keys if key != migration_origin_key]
            migration_destination_key = col_console_2.selectbox(
                "Consola de destino",
                options=migration_destination_options,
                index=migration_destination_options.index(migration_destination_default)
                if migration_destination_default in migration_destination_options else 0,
                format_func=lambda key: format_console_option(console_lookup[key]),
                key="migration_destination_console_key",
            )
        selected_migration_destination_console = console_lookup.get(migration_destination_key, {})
        selected_migration_source_console = console_lookup.get(migration_origin_key, {})
    else:
        migration_origin_key = ""
        migration_destination_key = ""
        st.warning("No hay consolas disponibles para esta migración.")

    prefill_client_id = selected_migration_source_console.get("client_id", "")
    prefill_client_secret = selected_migration_source_console.get("client_secret", "")
    prefill_api_base_url = selected_migration_source_console.get("api_base_url", API_BASE_URL)
    prefill_token_url = selected_migration_source_console.get("token_url", TOKEN_URL)
    prefill_scope = selected_migration_source_console.get("scope", DEFAULT_SCOPE)
    prefill_source_account_id = selected_migration_source_console.get("account_id", DEFAULT_SOURCE_ACCOUNT_ID)
    prefill_destination_account_token = selected_migration_destination_console.get("account_token", DEFAULT_DESTINATION_ACCOUNT_TOKEN)
    prefill_move_path = selected_migration_destination_console.get("move_path", DEFAULT_TARGET_MOVE_PATH)

    previous_source_console_key = st.session_state.get("_active_source_console_key")
    if migration_origin_key and migration_origin_key != previous_source_console_key:
        st.session_state["_active_source_console_key"] = migration_origin_key
        st.session_state["source_api_base_url"] = prefill_api_base_url
        st.session_state["source_token_url"] = prefill_token_url
        st.session_state["last_access_token"] = ""
        st.session_state.pop("listed_endpoints", None)
        st.session_state.pop("live_jobs_report_rows", None)
        st.session_state.pop("live_jobs_report_summary", None)

    if migration_destination_key and not prefill_destination_account_token:
        destination_account_ctx, destination_account_ctx_detail = get_nebula_account_context(
            selected_migration_destination_console.get("client_id", ""),
            selected_migration_destination_console.get("client_secret", ""),
            selected_migration_destination_console.get("scope", DEFAULT_TARGET_SCOPE),
            selected_migration_destination_console.get("token_url", DEFAULT_TARGET_TOKEN_URL),
            selected_migration_destination_console.get("api_base_url", DEFAULT_TARGET_API_BASE_URL),
            selected_migration_destination_console.get("account_id", ""),
        )
        if destination_account_ctx:
            prefill_destination_account_token = str(destination_account_ctx.get("account_token", "")).strip()
        elif selected_migration_destination_console.get("kind") == "Nebula":
            st.warning(
                "No se pudo resolver automáticamente el Account Token del destino seleccionado. "
                "Captúralo manualmente o revisa las credenciales de esa consola."
            )

    if migration_destination_key and not prefill_destination_account_token:
        st.warning("La consola de destino seleccionada no tiene Account Token configurado; debes capturarlo manualmente antes de migrar.")

    st.subheader("1) Obtener token del origen")
    with st.form("token_form"):
        client_id = st.text_input("Client ID", value=prefill_client_id, placeholder="Pega aquí tu client id")
        client_secret = st.text_input(
            "Client Secret",
            value=prefill_client_secret,
            placeholder="Pega aquí tu client secret",
            type="password",
        )
        api_base_url = st.text_input("API Base URL", value=prefill_api_base_url)
        token_url = st.text_input("Token URL", value=prefill_token_url)
        scope = st.text_input("Scope", value=prefill_scope)
        submitted = st.form_submit_button("Obtener token", use_container_width=True)

    if submitted:
        if not client_id.strip():
            st.error("Falta el Client ID.")
        elif not client_secret.strip():
            st.error("Falta el Client Secret.")
        else:
            with st.spinner("Solicitando token..."):
                token, payload = get_token(
                    client_id.strip(),
                    client_secret.strip(),
                    scope.strip() or DEFAULT_SCOPE,
                    token_url=token_url.strip() or TOKEN_URL,
                )

            if token:
                st.success("Token obtenido correctamente.")
                st.code(token, language="text")
                st.session_state["last_access_token"] = token
                st.session_state["source_token_url"] = token_url.strip() or TOKEN_URL
                st.session_state["source_api_base_url"] = api_base_url.strip() or API_BASE_URL

                with st.expander("Respuesta completa"):
                    st.json(payload)
            else:
                st.error("No se pudo obtener el token.")
                st.json(payload)

    st.divider()
    st.subheader("2) Listar endpoints")
    _src_method = selected_migration_source_console.get("endpoints_method", "POST").upper()
    _src_path = selected_migration_source_console.get("endpoints_path", DEFAULT_ENDPOINTS_PATH)
    st.caption(f"Método: {_src_method} · Ruta: {_src_path} · paginación automática")

    # Sección 2: valores fijos desde la consola activa, sin form
    _list_api_base_url = selected_migration_source_console.get("api_base_url", prefill_api_base_url)
    _list_endpoints_path = selected_migration_source_console.get("endpoints_path", DEFAULT_ENDPOINTS_PATH)
    _list_method = selected_migration_source_console.get("endpoints_method", "POST").upper()
    _list_account_id = selected_migration_source_console.get("account_id", prefill_source_account_id)
    st.caption(f"Base URL: `{_list_api_base_url}` · Ruta: `{_list_endpoints_path}` · Método: `{_list_method}` · Account ID: `{_list_account_id[:8]}…`")

    list_submitted = st.button("▶ Listar endpoints", use_container_width=True, type="primary")

    if list_submitted:
        with st.spinner("Autenticando..."):
            _use_token, _auto_payload = get_token(
                selected_migration_source_console.get("client_id", prefill_client_id),
                selected_migration_source_console.get("client_secret", prefill_client_secret),
                selected_migration_source_console.get("scope", DEFAULT_SCOPE),
                token_url=selected_migration_source_console.get("token_url", TOKEN_URL),
            )
        if not _use_token:
            st.error("No se pudo obtener el token. Revisa credenciales de la consola origen.")
            st.json(_auto_payload)
        else:
            st.session_state["last_access_token"] = _use_token
            with st.spinner("Consultando todos los endpoints..."):
                endpoints, list_detail = get_all_endpoints(
                    _use_token,
                    endpoints_path=_list_endpoints_path,
                    api_base_url=_list_api_base_url,
                    request_method=_list_method,
                    account_id=_list_account_id,
                    page_size=200,
                    max_pages=0,
                )

            if endpoints is not None:
                st.success(f"Endpoints obtenidos: {len(endpoints)}")
                st.json(list_detail)
                st.session_state["listed_endpoints"] = endpoints
                if not endpoints:
                    st.info("No se encontraron endpoints.")
            else:
                st.error("No se pudo listar endpoints.")
                st.json(list_detail)

    if st.session_state.get("listed_endpoints"):
        st.download_button(
            "⬇ Descargar listado completo (CSV)",
            data=endpoints_to_csv(st.session_state["listed_endpoints"]),
            file_name="endpoints.csv",
            mime="text/csv",
            use_container_width=True,
        )
        st.divider()
        st.subheader("3) Selección para migración")
        st.caption("Marca con checkbox los endpoints que quieres migrar.")

        with st.expander(f"🔍 Estructura del primer endpoint (diagnóstico)"):
            if st.session_state["listed_endpoints"]:
                st.json(st.session_state["listed_endpoints"][0])

        selection_rows = [endpoint_to_selection_row(ep) for ep in st.session_state["listed_endpoints"]]

        selection_df = pd.DataFrame(selection_rows)
        # Columnas deshabilitadas = todas menos 'migrar'
        _disabled_cols = [c for c in selection_df.columns if c != "migrar"]

        edited_df = st.data_editor(
            selection_df,
            hide_index=True,
            use_container_width=True,
            column_config={
                "migrar": st.column_config.CheckboxColumn("Migrar", help="Selecciona endpoint para migración"),
            },
            disabled=_disabled_cols,
            key="migration_selector_editor",
        )

        selected_df = edited_df[edited_df["migrar"] == True]  # noqa: E712
        selected_rows = selected_df.to_dict(orient="records")

        st.info(f"Seleccionados para migrar: {len(selected_rows)}")

        if selected_rows:
            st.download_button(
                "Descargar selección (JSON)",
                data=json.dumps(selected_rows, indent=2),
                file_name="selected_endpoints_for_migration.json",
                mime="application/json",
                use_container_width=True,
            )
            st.download_button(
                "Descargar selección (CSV)",
                data=selected_ids_to_csv(selected_rows),
                file_name="selected_endpoints_for_migration.csv",
                mime="text/csv",
                use_container_width=True,
            )
            with st.expander("Vista previa de selección"):
                st.dataframe(selected_df, use_container_width=True)

        st.divider()
        st.subheader("4) Ejecutar migración")
        st.caption("Crea un job en el origen para cambiar el account token de los endpoints seleccionados.")

        # Campo a usar como machine_id — para MLTi es siempre "machine_id" en raíz
        _sample_ep = st.session_state["listed_endpoints"][0] if st.session_state.get("listed_endpoints") else {}
        _ep_fields = [k for k, v in _sample_ep.items() if isinstance(v, str) and v.strip()]
        _default_id_field = "machine_id" if "machine_id" in _ep_fields else (_ep_fields[0] if _ep_fields else "machine_id")

        with st.expander("Diagnóstico endpoint de move"):
            st.caption("Prueba rutas candidatas de jobs. Si responde distinto de 404, la ruta existe.")
            probe_move_token = st.text_input(
                "Access Token de origen para diagnóstico",
                value=st.session_state.get("last_access_token", ""),
                type="password",
                key="probe_move_token",
            )
            probe_move_base_url = st.text_input(
                "API Base URL para diagnóstico",
                value=st.session_state.get("source_api_base_url", API_BASE_URL),
                key="probe_move_base_url",
            )
            probe_move_accountid = st.text_input(
                "Header accountid para diagnóstico",
                value=prefill_source_account_id,
                key="probe_move_accountid",
            )
            move_candidate_paths = st.text_area(
                "Rutas candidatas de jobs (una por línea)",
                value="\n".join(DEFAULT_MOVE_CANDIDATE_PATHS),
                height=120,
                key="move_candidate_paths",
            )
            if st.button("Probar rutas de jobs", use_container_width=True):
                if not probe_move_token.strip():
                    st.error("Falta Access Token de origen para diagnóstico.")
                else:
                    with st.spinner("Probando rutas de jobs..."):
                        move_probe_result = probe_move_paths(
                            access_token=probe_move_token.strip(),
                            api_base_url=probe_move_base_url.strip() or API_BASE_URL,
                            candidate_paths_text=move_candidate_paths,
                            accountid_header=probe_move_accountid.strip(),
                        )
                    st.dataframe(move_probe_result, use_container_width=True)
                    candidates = [r for r in move_probe_result if r.get("exists_not_404")]
                    if candidates:
                        st.success(
                            "Rutas candidatas existentes: "
                            + ", ".join([f"{r['path']} (status {r['status']})" for r in candidates])
                        )
                    else:
                        st.warning("Todas las rutas devolvieron 404. Revisa host/API version del tenant origen.")

        with st.form("execute_migration_form"):
            origin_access_token_for_move = st.text_input(
                "Access Token de origen",
                value=st.session_state.get("last_access_token", ""),
                type="password",
            )
            origin_api_base_url_for_move = st.text_input(
                "API Base URL de origen",
                value=st.session_state.get("source_api_base_url", API_BASE_URL),
            )
            source_account_id_for_move = st.text_input(
                "Source Account ID (header accountid)",
                value=prefill_source_account_id,
            )
            destination_account_token = st.text_input(
                "Destination Account Token",
                value=prefill_destination_account_token,
                type="password",
            )
            move_path = st.text_input("Jobs Path", value=prefill_move_path)
            migration_command = st.text_input("Command", value=DEFAULT_MIGRATION_COMMAND)
            machine_id_field = st.selectbox(
                "Campo a usar como machine_id",
                options=_ep_fields or ["id"],
                index=(_ep_fields.index(_default_id_field) if _default_id_field in _ep_fields else 0),
                help="Campo del endpoint que se enviará como machine_ids al job. Revisa el diagnóstico del endpoint si la lista está vacía.",
            )
            batch_size = st.selectbox("Tamano de batch", options=[1, 5, 10], index=1)
            dry_run = st.checkbox("Dry run (solo simular y mostrar payload)", value=True)
            execute_migration = st.form_submit_button("Ejecutar migración", use_container_width=True)

        if execute_migration:
            if not selected_rows:
                st.error("No hay endpoints seleccionados. Marca al menos uno en el paso 3.")
            elif not origin_access_token_for_move.strip():
                st.error("Falta Access Token de origen para ejecutar el job de migración.")
            elif not source_account_id_for_move.strip():
                st.error("Falta Source Account ID para el header accountid.")
            else:
                effective_destination_account_token = destination_account_token.strip()
                if not effective_destination_account_token:
                    destination_account_ctx, destination_account_ctx_detail = get_nebula_account_context(
                        selected_migration_destination_console.get("client_id", ""),
                        selected_migration_destination_console.get("client_secret", ""),
                        selected_migration_destination_console.get("scope", DEFAULT_TARGET_SCOPE),
                        selected_migration_destination_console.get("token_url", DEFAULT_TARGET_TOKEN_URL),
                        selected_migration_destination_console.get("api_base_url", DEFAULT_TARGET_API_BASE_URL),
                        selected_migration_destination_console.get("account_id", ""),
                    )
                    if destination_account_ctx:
                        effective_destination_account_token = str(
                            destination_account_ctx.get("account_token", "")
                        ).strip()

                if not effective_destination_account_token:
                    st.error("Falta Destination Account Token y no se pudo resolver automáticamente desde la consola destino.")
                    st.json(destination_account_ctx_detail if 'destination_account_ctx_detail' in locals() else {})
                    st.stop()

                selected_batches = chunk_rows(selected_rows, int(batch_size))

                # Verificar que se puedan extraer machine_ids antes de proceder
                _preview_ids = []
                for _r in selected_rows:
                    if machine_id_field == "machine.id":
                        _m = _r.get("machine", {})
                        _mid = _m.get("id", "") if isinstance(_m, dict) else ""
                    else:
                        _mid = str(_r.get(machine_id_field, "")).strip()
                    if _mid:
                        _preview_ids.append(_mid)
                if not _preview_ids:
                    st.error(
                        f"El campo `{machine_id_field}` está vacío en todos los endpoints seleccionados. "
                        f"Campos disponibles: {_ep_fields}"
                    )
                    st.json(_sample_ep)
                    st.stop()

                effective_move_path = move_path.strip() or DEFAULT_TARGET_MOVE_PATH
                # Compatibilidad: el comando changeaccounttoken se ejecuta en /nebula/v1/jobs.
                if effective_move_path.rstrip("/") in {"/nebula/v1/endpoints/move", "/v1/endpoints/move"}:
                    st.warning(
                        "La ruta de move antigua fue ajustada automáticamente a /nebula/v1/jobs "
                        "para command.engine.changeaccounttoken."
                    )
                    effective_move_path = "/nebula/v1/jobs"

                dry_run_payloads = []
                for batch_index, batch_rows in enumerate(selected_batches, start=1):
                    payload_variants = build_migration_payload_variants(
                        batch_rows,
                        destination_account_token=effective_destination_account_token,
                        command_name=migration_command.strip() or DEFAULT_MIGRATION_COMMAND,
                        machine_id_field=machine_id_field,
                    )
                    for variant in payload_variants:
                        dry_run_payloads.append(
                            {
                                "batch": batch_index,
                                "batch_size": len(batch_rows),
                                "payload": variant,
                            }
                        )

                st.write("Payload(s) preparado(s) por batch:")
                st.json(dry_run_payloads)

                if dry_run:
                    st.success("Dry run completado. No se enviaron cambios al destino.")
                else:
                    batch_results = []
                    total_ok = 0
                    total_fail = 0

                    for batch_index, batch_rows in enumerate(selected_batches, start=1):
                        payload_variants = build_migration_payload_variants(
                            batch_rows,
                            destination_account_token=effective_destination_account_token,
                            command_name=migration_command.strip() or DEFAULT_MIGRATION_COMMAND,
                            machine_id_field=machine_id_field,
                        )

                        with st.spinner(
                            f"Ejecutando batch {batch_index}/{len(selected_batches)} "
                            f"({len(batch_rows)} endpoint(s))..."
                        ):
                            ok, migration_result = run_migration_request(
                                access_token=origin_access_token_for_move.strip(),
                                api_base_url=origin_api_base_url_for_move.strip() or API_BASE_URL,
                                jobs_path=effective_move_path,
                                origin_account_id=source_account_id_for_move.strip(),
                                payload_variants=payload_variants,
                            )

                        batch_results.append(
                            {
                                "batch": batch_index,
                                "batch_size": len(batch_rows),
                                "machine_ids": [mid for r in batch_rows if (mid := _get_mid_for_log(r, machine_id_field))],
                                "ok": ok,
                                "result": migration_result,
                            }
                        )
                        if ok:
                            total_ok += 1
                        else:
                            total_fail += 1

                    if total_fail == 0:
                        st.success(
                            f"Migración enviada por batches. Exitosos: {total_ok}/{len(selected_batches)}"
                        )
                    else:
                        st.error(
                            f"Migración con errores por batch. Exitosos: {total_ok}, Fallidos: {total_fail}"
                        )
                    st.json(
                        {
                            "total_selected": len(selected_rows),
                            "batch_size": int(batch_size),
                            "total_batches": len(selected_batches),
                            "ok_batches": total_ok,
                            "failed_batches": total_fail,
                            "batches": batch_results,
                        }
                    )

                    # Persistir el ultimo resultado para reporte vivo de estado.
                    st.session_state["last_batch_results"] = batch_results
                    st.session_state["last_migration_context"] = {
                        "access_token": origin_access_token_for_move.strip(),
                        "api_base_url": origin_api_base_url_for_move.strip() or API_BASE_URL,
                        "source_account_id": source_account_id_for_move.strip(),
                    }
                    st.session_state["last_job_ids"] = extract_job_ids_from_batch_results(batch_results)

        st.divider()
        st.subheader("5) Reporte vivo de migración")
        st.caption("Consulta el estado real de los jobs y actualiza el porcentaje completado con el botón Refresh.")

        live_ctx = st.session_state.get("last_migration_context", {})
        default_live_token = live_ctx.get("access_token", st.session_state.get("last_access_token", ""))
        default_live_api_base = live_ctx.get("api_base_url", st.session_state.get("source_api_base_url", API_BASE_URL))
        default_live_account = live_ctx.get("source_account_id", DEFAULT_SOURCE_ACCOUNT_ID)
        default_live_job_ids = st.session_state.get("last_job_ids", [])

        live_access_token = st.text_input(
            "Access Token para reporte",
            value=default_live_token,
            type="password",
            key="live_report_access_token",
        )
        live_api_base_url = st.text_input(
            "API Base URL para reporte",
            value=default_live_api_base,
            key="live_report_api_base",
        )
        live_account_id = st.text_input(
            "Source Account ID para reporte",
            value=default_live_account,
            key="live_report_account_id",
        )
        live_job_ids_text = st.text_area(
            "Job IDs (uno por línea)",
            value="\n".join(default_live_job_ids),
            height=180,
            key="live_report_job_ids",
        )

        refresh_jobs = st.button("Refresh estado de jobs", use_container_width=True, type="primary")

        if refresh_jobs:
            job_ids = []
            for line in live_job_ids_text.splitlines():
                jid = line.strip()
                if jid and jid not in job_ids:
                    job_ids.append(jid)

            if not live_access_token.strip():
                st.error("Falta Access Token para consultar estado de jobs.")
            elif not job_ids:
                st.error("Faltan Job IDs para consultar el reporte.")
            else:
                with st.spinner("Consultando estado de jobs..."):
                    report_rows, report_summary = get_jobs_status_report(
                        access_token=live_access_token.strip(),
                        api_base_url=live_api_base_url.strip() or API_BASE_URL,
                        origin_account_id=live_account_id.strip(),
                        job_ids=job_ids,
                    )

                st.session_state["live_jobs_report_rows"] = report_rows
                st.session_state["live_jobs_report_summary"] = report_summary
                st.session_state["last_job_ids"] = job_ids

        if st.session_state.get("live_jobs_report_summary"):
            summary = st.session_state["live_jobs_report_summary"]
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Total jobs", int(summary.get("total_jobs", 0)))
            col2.metric("Completed", int(summary.get("completed", 0)))
            col3.metric("Pending", int(summary.get("pending", 0)))
            col4.metric("Failed", int(summary.get("failed", 0)))

            completion_pct = float(summary.get("completion_pct", 0.0))
            st.progress(min(max(completion_pct / 100.0, 0.0), 1.0), text=f"Completado: {completion_pct:.2f}%")

            if st.session_state.get("live_jobs_report_rows"):
                report_df = pd.DataFrame(st.session_state["live_jobs_report_rows"])
                st.dataframe(report_df, use_container_width=True)

with tab_edron:
    st.subheader("Inventario OneView de Edron")
    st.caption("Lista completa de equipos de Edron, seleccionable y exportable en CSV/XLSX.")

    st.subheader("Consolas de la migración Edron")
    if oneview_console_keys:
        col_edron_1, col_edron_2 = st.columns(2)
        edron_origin_key = col_edron_1.selectbox(
            "Consola de origen",
            options=oneview_console_keys,
            index=oneview_console_keys.index(edron_source_default),
            format_func=lambda key: format_console_option(console_lookup[key]),
            key="edron_origin_console_key",
        )
        edron_destination_key = col_edron_2.selectbox(
            "Consola de destino",
            options=nebula_console_keys,
            index=nebula_console_keys.index(edron_destination_default) if edron_destination_default in nebula_console_keys else 0,
            format_func=lambda key: format_console_option(console_lookup[key]),
            key="edron_destination_console_key",
        )
        selected_edron_source_console = console_lookup[edron_origin_key]
        selected_edron_destination_console = console_lookup[edron_destination_key]
        st.caption(
            "Origen activo: "
            f"{format_console_option(selected_edron_source_console)} | "
            f"Destino activo: {format_console_option(selected_edron_destination_console)}"
        )
    else:
        edron_origin_key = ""
        edron_destination_key = ""
        st.warning("No hay consola OneView configurada para esta migración.")

    with st.expander("Destino Nebula (no registrado)", expanded=False):
        st.caption("Configura aquí la consola destino sin usar .env. Se guarda en esta sesión.")
        with st.form("edron_target_console_form"):
            target_client_id_ad_hoc = st.text_input(
                "Target Client ID",
                value=selected_edron_destination_console.get("client_id", st.session_state.get("target_client_id", DEFAULT_TARGET_CLIENT_ID)),
            )
            target_client_secret_ad_hoc = st.text_input(
                "Target Client Secret",
                value=selected_edron_destination_console.get("client_secret", st.session_state.get("target_client_secret", DEFAULT_TARGET_CLIENT_SECRET)),
                type="password",
            )
            target_token_url_ad_hoc = st.text_input(
                "Target Token URL",
                value=selected_edron_destination_console.get("token_url", st.session_state.get("target_token_url", DEFAULT_TARGET_TOKEN_URL)),
            )
            target_scope_ad_hoc = st.text_input(
                "Target Scope",
                value=selected_edron_destination_console.get("scope", st.session_state.get("target_scope", DEFAULT_TARGET_SCOPE)),
            )
            target_api_base_ad_hoc = st.text_input(
                "Target API Base URL",
                value=selected_edron_destination_console.get("api_base_url", st.session_state.get("target_api_base_url", DEFAULT_TARGET_API_BASE_URL)),
            )
            destination_account_token_ad_hoc = st.text_input(
                "Destination Account Token",
                value=selected_edron_destination_console.get("account_token", st.session_state.get("target_destination_account_token", DEFAULT_DESTINATION_ACCOUNT_TOKEN)),
                type="password",
                help="Token de cuenta destino usado por command.engine.changeaccounttoken.",
            )
            save_target_config = st.form_submit_button("Guardar configuración destino", use_container_width=True)

        if save_target_config:
            st.session_state["target_client_id"] = target_client_id_ad_hoc.strip()
            st.session_state["target_client_secret"] = target_client_secret_ad_hoc.strip()
            st.session_state["target_token_url"] = target_token_url_ad_hoc.strip()
            st.session_state["target_scope"] = target_scope_ad_hoc.strip() or DEFAULT_TARGET_SCOPE
            st.session_state["target_api_base_url"] = target_api_base_ad_hoc.strip() or DEFAULT_TARGET_API_BASE_URL
            st.session_state["target_destination_account_token"] = destination_account_token_ad_hoc.strip()
            st.success("Configuración de destino guardada para esta sesión.")

        if st.button("Probar credenciales de destino", use_container_width=True):
            target_client_id = st.session_state.get("target_client_id", "")
            target_client_secret = st.session_state.get("target_client_secret", "")
            target_token_url = st.session_state.get("target_token_url", DEFAULT_TARGET_TOKEN_URL)
            target_scope = st.session_state.get("target_scope", DEFAULT_TARGET_SCOPE)

            if not target_client_id or not target_client_secret:
                st.error("Faltan Target Client ID/Secret para probar autenticación.")
            else:
                with st.spinner("Probando autenticación en consola destino..."):
                    target_token, target_detail = get_token(
                        target_client_id,
                        target_client_secret,
                        target_scope,
                        token_url=target_token_url,
                    )
                if target_token:
                    st.success("Autenticación de destino correcta.")
                    st.session_state["target_access_token"] = target_token
                else:
                    st.error("No se pudo autenticar en la consola destino.")
                    st.json(target_detail)

    with st.form("edron_oneview_form"):
        edron_client_id = st.text_input(
            "Client ID",
            value=selected_edron_source_console.get("client_id", DEFAULT_EDRON_CLIENT_ID),
            placeholder="TD_CLIENT_ID_2",
        )
        edron_client_secret = st.text_input(
            "Client Secret",
            value=selected_edron_source_console.get("client_secret", DEFAULT_EDRON_CLIENT_SECRET),
            placeholder="TD_CLIENT_SECRET_2",
            type="password",
        )
        edron_api_base = st.text_input(
            "OneView API Base URL",
            value=selected_edron_source_console.get("api_base_url", DEFAULT_ONEVIEW_API_BASE_URL),
            help="Ejemplo: https://api.malwarebytes.com",
        )
        edron_token_url = st.text_input(
            "OneView Token URL",
            value=selected_edron_source_console.get("token_url", DEFAULT_ONEVIEW_TOKEN_URL),
            help="Ejemplo: https://api.malwarebytes.com/oneview/oauth2/token",
        )
        edron_scope = st.text_input("Scope", value=selected_edron_source_console.get("scope", DEFAULT_ONEVIEW_SCOPE))
        edron_page_size = st.number_input("Page size", min_value=1, max_value=500, value=200, step=1)
        edron_max_pages = st.number_input("Max pages (0 = sin límite)", min_value=0, max_value=1000, value=0, step=1)
        only_edron = st.checkbox("Filtrar solo sites con 'Edron' en company_name", value=True)

        load_edron = st.form_submit_button("Cargar equipos de Edron", use_container_width=True)

    if load_edron:
        if not edron_client_id.strip() or not edron_client_secret.strip():
            st.error("Faltan credenciales de Edron (Client ID / Client Secret).")
        else:
            with st.spinner("Obteniendo token OneView..."):
                token, token_detail = get_token(
                    edron_client_id.strip(),
                    edron_client_secret.strip(),
                    edron_scope.strip() or DEFAULT_ONEVIEW_SCOPE,
                    token_url=edron_token_url.strip() or DEFAULT_ONEVIEW_TOKEN_URL,
                )

            if not token:
                st.error("No se pudo obtener token de OneView.")
                st.json(token_detail)
            else:
                with st.spinner("Consultando sites y endpoints..."):
                    sites, sites_detail = get_oneview_sites(
                        access_token=token,
                        api_base_url=edron_api_base.strip() or DEFAULT_ONEVIEW_API_BASE_URL,
                    )

                if sites is None:
                    st.error("No se pudo obtener /oneview/v1/sites.")
                    st.json(sites_detail)
                else:
                    site_rows = []
                    for site in sites:
                        account_id = str(site.get("nebula_account_id", "")).strip()
                        company_name = str(site.get("company_name", "")).strip()
                        if account_id:
                            site_rows.append({
                                "account_id": account_id,
                                "company_name": company_name,
                            })

                    if only_edron:
                        filtered_sites = [
                            row for row in site_rows if "edron" in row.get("company_name", "").lower()
                        ]
                    else:
                        filtered_sites = site_rows

                    account_ids = list(dict.fromkeys([row["account_id"] for row in filtered_sites if row.get("account_id")]))

                    if not account_ids:
                        st.error("No se encontraron nebula_account_id válidos para consultar endpoints.")
                        st.json({"sites_detail": sites_detail, "sites_found": site_rows})
                    else:
                        endpoints, endpoints_detail = get_oneview_endpoints(
                            access_token=token,
                            api_base_url=edron_api_base.strip() or DEFAULT_ONEVIEW_API_BASE_URL,
                            account_ids=account_ids,
                            page_size=int(edron_page_size),
                            max_pages=int(edron_max_pages),
                        )

                        if endpoints is None:
                            st.error("No se pudieron obtener endpoints de OneView.")
                            st.json(endpoints_detail)
                        else:
                            st.session_state["edron_sites"] = filtered_sites
                            st.session_state["edron_oneview_endpoints"] = endpoints
                            st.session_state["edron_account_ids"] = account_ids
                            st.session_state["edron_access_token"] = token
                            st.session_state["edron_api_base_url"] = edron_api_base.strip() or DEFAULT_ONEVIEW_API_BASE_URL
                            st.success(f"Equipos cargados: {len(endpoints)}")
                            st.json({
                                "sites_total": len(site_rows),
                                "sites_filtrados": len(filtered_sites),
                                "account_ids": account_ids,
                                "endpoints_detail": endpoints_detail,
                            })

    edron_endpoints = st.session_state.get("edron_oneview_endpoints", [])
    if edron_endpoints:
        rows = [oneview_endpoint_to_selection_row(ep) for ep in edron_endpoints]
        edron_df = pd.DataFrame(rows)

        st.divider()
        st.subheader("Lista de equipos de Edron")
        st.caption("Selecciona los equipos que quieras usar en la siguiente etapa de migración.")

        edited_df = st.data_editor(
            edron_df,
            hide_index=True,
            use_container_width=True,
            column_config={
                "migrar": st.column_config.CheckboxColumn("Seleccionar"),
                "display_name": st.column_config.TextColumn("Equipo"),
                "machine_id": st.column_config.TextColumn("Machine ID"),
                "account_id": st.column_config.TextColumn("Account ID"),
                "connected": st.column_config.CheckboxColumn("Conectado"),
                "last_seen_at": st.column_config.TextColumn("Last seen"),
                "policy_name": st.column_config.TextColumn("Policy"),
                "group_name": st.column_config.TextColumn("Group"),
            },
            disabled=["display_name", "machine_id", "account_id", "connected", "last_seen_at", "policy_name", "group_name"],
            key="edron_selector_editor",
        )

        selected_df = edited_df[edited_df["migrar"] == True]  # noqa: E712
        st.info(f"Seleccionados: {len(selected_df)} de {len(edited_df)}")

        if not selected_df.empty:
            selected_export_df = selected_df.drop(columns=["migrar"])
            if st.button("Guardar selección con consecutivos (SQLite)", use_container_width=True, type="primary"):
                save_detail = save_edron_selection_with_consecutivos(selected_export_df.to_dict(orient="records"))
                st.success(
                    "Lista guardada en oneview_to_nebula.db: "
                    f"nuevos={save_detail['inserted']}, actualizados={save_detail['updated']}, "
                    f"omitidos={save_detail['skipped']}, total_tracking={save_detail['total_tracking']}"
                )

            st.download_button(
                "Exportar seleccionados (CSV)",
                data=selected_export_df.to_csv(index=False),
                file_name="edron_endpoints_selected.csv",
                mime="text/csv",
                use_container_width=True,
            )
            st.download_button(
                "Exportar seleccionados (XLSX)",
                data=dataframe_to_excel_bytes(selected_export_df),
                file_name="edron_endpoints_selected.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                use_container_width=True,
            )

            st.session_state["edron_selected_rows"] = selected_export_df.to_dict(orient="records")
        else:
            st.session_state["edron_selected_rows"] = []

        st.download_button(
            "Exportar todos (CSV)",
            data=edron_df.drop(columns=["migrar"]).to_csv(index=False),
            file_name="edron_endpoints_all.csv",
            mime="text/csv",
            use_container_width=True,
        )
        st.download_button(
            "Exportar todos (XLSX)",
            data=dataframe_to_excel_bytes(edron_df.drop(columns=["migrar"])),
            file_name="edron_endpoints_all.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            use_container_width=True,
        )

        st.divider()
        st.subheader("Migracion / premigracion desde Edron")
        st.caption("Simula o ejecuta command.engine.changeaccounttoken para los equipos seleccionados.")

        edron_selected_rows = st.session_state.get("edron_selected_rows", [])
        with st.form("execute_edron_migration_form"):
            edron_origin_access_token = st.text_input(
                "Access Token de origen (OneView)",
                value=st.session_state.get("edron_access_token", ""),
                type="password",
            )
            edron_origin_api_base_url = st.text_input(
                "API Base URL de origen",
                value=st.session_state.get("edron_api_base_url", DEFAULT_ONEVIEW_API_BASE_URL),
                help="Se usa para enviar el job al tenant origen de Edron.",
            )
            edron_destination_account_token = st.text_input(
                "Destination Account Token",
                value=selected_edron_destination_console.get(
                    "account_token",
                    st.session_state.get("target_destination_account_token", DEFAULT_DESTINATION_ACCOUNT_TOKEN),
                ),
                type="password",
            )
            edron_move_path = st.text_input(
                "Jobs Path",
                value=selected_edron_destination_console.get("move_path", DEFAULT_TARGET_MOVE_PATH),
            )
            edron_migration_command = st.text_input("Command", value=DEFAULT_MIGRATION_COMMAND)
            edron_batch_size = st.selectbox("Tamano de batch", options=[1, 5, 10], index=1)
            edron_dry_run = st.checkbox("Dry run (solo simular y mostrar payload)", value=True)
            execute_edron_migration = st.form_submit_button("Ejecutar migracion Edron", use_container_width=True)

        if execute_edron_migration:
            if not edron_selected_rows:
                st.error("No hay equipos seleccionados en Edron. Marca al menos uno antes de migrar.")
            elif not edron_origin_access_token.strip():
                st.error("Falta Access Token de origen (OneView).")
            else:
                effective_edron_destination_account_token = edron_destination_account_token.strip()
                if not effective_edron_destination_account_token:
                    edron_destination_ctx, edron_destination_ctx_detail = get_nebula_account_context(
                        selected_edron_destination_console.get("client_id", ""),
                        selected_edron_destination_console.get("client_secret", ""),
                        selected_edron_destination_console.get("scope", DEFAULT_TARGET_SCOPE),
                        selected_edron_destination_console.get("token_url", DEFAULT_TARGET_TOKEN_URL),
                        selected_edron_destination_console.get("api_base_url", DEFAULT_TARGET_API_BASE_URL),
                        selected_edron_destination_console.get("account_id", ""),
                    )
                    if edron_destination_ctx:
                        effective_edron_destination_account_token = str(
                            edron_destination_ctx.get("account_token", "")
                        ).strip()

                if not effective_edron_destination_account_token:
                    st.error("Falta Destination Account Token y no se pudo resolver automáticamente desde la consola destino.")
                    st.json(edron_destination_ctx_detail if 'edron_destination_ctx_detail' in locals() else {})
                    st.stop()

                grouped_rows = {}
                for row in edron_selected_rows:
                    account_id = str(row.get("account_id", "")).strip()
                    grouped_rows.setdefault(account_id, []).append(row)

                effective_move_path = edron_move_path.strip() or DEFAULT_TARGET_MOVE_PATH
                if effective_move_path.rstrip("/") in {"/nebula/v1/endpoints/move", "/v1/endpoints/move"}:
                    st.warning(
                        "La ruta de move antigua fue ajustada automaticamente a /nebula/v1/jobs "
                        "para command.engine.changeaccounttoken."
                    )
                    effective_move_path = "/nebula/v1/jobs"

                edron_batches = []
                for account_id, account_rows in grouped_rows.items():
                    for batch_index, batch_rows in enumerate(chunk_rows(account_rows, int(edron_batch_size)), start=1):
                        edron_batches.append(
                            {
                                "account_id": account_id,
                                "batch_index": batch_index,
                                "rows": batch_rows,
                            }
                        )

                dry_run_payloads = []
                for batch in edron_batches:
                    payload_variants = build_migration_payload_variants(
                        batch["rows"],
                        destination_account_token=effective_edron_destination_account_token,
                        command_name=edron_migration_command.strip() or DEFAULT_MIGRATION_COMMAND,
                    )
                    for variant in payload_variants:
                        dry_run_payloads.append(
                            {
                                "account_id": batch["account_id"],
                                "batch": batch["batch_index"],
                                "batch_size": len(batch["rows"]),
                                "payload": variant,
                            }
                        )

                st.write("Payload(s) preparado(s) por batch y account_id:")
                st.json(dry_run_payloads)

                if edron_dry_run:
                    st.success("Dry run completado. No se enviaron cambios al destino.")
                else:
                    batch_results = []
                    total_ok = 0
                    total_fail = 0

                    for batch in edron_batches:
                        payload_variants = build_migration_payload_variants(
                            batch["rows"],
                            destination_account_token=effective_edron_destination_account_token,
                            command_name=edron_migration_command.strip() or DEFAULT_MIGRATION_COMMAND,
                        )

                        with st.spinner(
                            f"Ejecutando account_id {batch['account_id'] or '(sin account_id)'} "
                            f"batch {batch['batch_index']} ({len(batch['rows'])} endpoint(s))..."
                        ):
                            ok, migration_result = run_migration_request(
                                access_token=edron_origin_access_token.strip(),
                                api_base_url=edron_origin_api_base_url.strip() or DEFAULT_ONEVIEW_API_BASE_URL,
                                jobs_path=effective_move_path,
                                origin_account_id=batch["account_id"],
                                payload_variants=payload_variants,
                            )

                        batch_results.append(
                            {
                                "account_id": batch["account_id"],
                                "batch": batch["batch_index"],
                                "batch_size": len(batch["rows"]),
                                "machine_ids": [r.get("machine_id", "") for r in batch["rows"] if r.get("machine_id")],
                                "ok": ok,
                                "result": migration_result,
                            }
                        )
                        if ok:
                            total_ok += 1
                        else:
                            total_fail += 1

                    if total_fail == 0:
                        st.success(
                            f"Migracion Edron enviada por batches. Exitosos: {total_ok}/{len(edron_batches)}"
                        )
                    else:
                        st.error(
                            f"Migracion Edron con errores por batch. Exitosos: {total_ok}, Fallidos: {total_fail}"
                        )

                    st.json(
                        {
                            "total_selected": len(edron_selected_rows),
                            "total_batches": len(edron_batches),
                            "batch_size": int(edron_batch_size),
                            "ok_batches": total_ok,
                            "failed_batches": total_fail,
                            "batches": batch_results,
                        }
                    )

                    st.session_state["edron_last_batch_results"] = batch_results
                    st.session_state["edron_last_migration_context"] = {
                        "access_token": edron_origin_access_token.strip(),
                        "api_base_url": edron_origin_api_base_url.strip() or DEFAULT_ONEVIEW_API_BASE_URL,
                    }
                    st.session_state["edron_last_job_records"] = extract_job_records_from_batch_results(batch_results)

        st.divider()
        st.subheader("Reporte vivo de migracion Edron")
        st.caption("Consulta el estado real de los jobs de Edron y revisa si siguen en pending.")

        edron_live_ctx = st.session_state.get("edron_last_migration_context", {})
        default_edron_live_token = edron_live_ctx.get("access_token", st.session_state.get("edron_access_token", ""))
        default_edron_live_api_base = edron_live_ctx.get(
            "api_base_url",
            st.session_state.get("edron_api_base_url", DEFAULT_ONEVIEW_API_BASE_URL),
        )
        default_edron_job_records = st.session_state.get("edron_last_job_records", [])
        default_edron_job_lines = [
            record["job_id"] + (f"|{record['account_id']}" if record.get("account_id") else "")
            for record in default_edron_job_records
            if isinstance(record, dict) and record.get("job_id")
        ]

        edron_live_access_token = st.text_input(
            "Access Token para reporte Edron",
            value=default_edron_live_token,
            type="password",
            key="edron_live_report_access_token",
        )
        edron_live_api_base_url = st.text_input(
            "API Base URL para reporte Edron",
            value=default_edron_live_api_base,
            key="edron_live_report_api_base",
        )
        edron_live_job_ids_text = st.text_area(
            "Job IDs Edron (uno por linea, opcionalmente job_id|account_id)",
            value="\n".join(default_edron_job_lines),
            height=180,
            key="edron_live_report_job_ids",
        )

        refresh_edron_jobs = st.button(
            "Refresh estado de jobs Edron",
            use_container_width=True,
            type="primary",
            key="refresh_edron_jobs",
        )

        if refresh_edron_jobs:
            job_records = []
            for line in edron_live_job_ids_text.splitlines():
                raw = line.strip()
                if not raw:
                    continue
                if "|" in raw:
                    job_id, account_id = raw.split("|", 1)
                else:
                    job_id, account_id = raw, ""
                record = {"job_id": job_id.strip(), "account_id": account_id.strip()}
                if record["job_id"] and record not in job_records:
                    job_records.append(record)

            if not edron_live_access_token.strip():
                st.error("Falta Access Token para consultar estado de jobs de Edron.")
            elif not job_records:
                st.error("Faltan Job IDs para consultar el reporte de Edron.")
            else:
                with st.spinner("Consultando estado de jobs de Edron..."):
                    report_rows, report_summary = get_jobs_status_report_by_records(
                        access_token=edron_live_access_token.strip(),
                        api_base_url=edron_live_api_base_url.strip() or DEFAULT_ONEVIEW_API_BASE_URL,
                        job_records=job_records,
                    )

                st.session_state["edron_live_jobs_report_rows"] = report_rows
                st.session_state["edron_live_jobs_report_summary"] = report_summary
                st.session_state["edron_last_job_records"] = job_records

        if st.session_state.get("edron_live_jobs_report_summary"):
            summary = st.session_state["edron_live_jobs_report_summary"]
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Total jobs", int(summary.get("total_jobs", 0)))
            col2.metric("Completed", int(summary.get("completed", 0)))
            col3.metric("Pending", int(summary.get("pending", 0)))
            col4.metric("Failed", int(summary.get("failed", 0)))

            completion_pct = float(summary.get("completion_pct", 0.0))
            st.progress(min(max(completion_pct / 100.0, 0.0), 1.0), text=f"Completado: {completion_pct:.2f}%")

            if st.session_state.get("edron_live_jobs_report_rows"):
                report_df = pd.DataFrame(st.session_state["edron_live_jobs_report_rows"])
                st.dataframe(report_df, use_container_width=True)

        st.divider()
        st.subheader("Tracking de migración (consecutivos)")
        tracking_df = load_edron_tracking_df()
        if tracking_df.empty:
            st.info("Aún no hay lista guardada. Selecciona equipos y usa 'Guardar selección con consecutivos (SQLite)'.")
        else:
            st.caption("Marca la columna 'migrado' para llevar control de equipos ya migrados.")
            tracking_edited = st.data_editor(
                tracking_df,
                hide_index=True,
                use_container_width=True,
                column_config={
                    "consecutivo": st.column_config.NumberColumn("Consecutivo"),
                    "machine_id": st.column_config.TextColumn("Machine ID"),
                    "display_name": st.column_config.TextColumn("Equipo"),
                    "account_id": st.column_config.TextColumn("Account ID"),
                    "policy_name": st.column_config.TextColumn("Policy"),
                    "group_name": st.column_config.TextColumn("Group"),
                    "last_seen_at": st.column_config.TextColumn("Last seen"),
                    "migrado": st.column_config.CheckboxColumn("Migrado"),
                    "selected_at": st.column_config.TextColumn("Agregado"),
                    "migrated_at": st.column_config.TextColumn("Fecha migrado"),
                },
                disabled=[
                    "consecutivo",
                    "machine_id",
                    "display_name",
                    "account_id",
                    "policy_name",
                    "group_name",
                    "last_seen_at",
                    "selected_at",
                    "migrated_at",
                ],
                key="edron_tracking_editor",
            )

            col_t1, col_t2 = st.columns(2)
            if col_t1.button("Guardar cambios de estado", use_container_width=True):
                update_edron_tracking_migrado(tracking_edited.to_dict(orient="records"))
                st.success("Estados de migración actualizados.")

            if col_t2.button("Recargar tracking", use_container_width=True):
                st.rerun()

            migrados = int(tracking_edited[tracking_edited["migrado"] == True].shape[0])  # noqa: E712
            total = int(tracking_edited.shape[0])
            st.info(f"Migrados: {migrados} de {total}")

            st.download_button(
                "Exportar tracking (CSV)",
                data=tracking_edited.to_csv(index=False),
                file_name="edron_migration_tracking.csv",
                mime="text/csv",
                use_container_width=True,
            )
            st.download_button(
                "Exportar tracking (XLSX)",
                data=dataframe_to_excel_bytes(tracking_edited),
                file_name="edron_migration_tracking.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                use_container_width=True,
            )
