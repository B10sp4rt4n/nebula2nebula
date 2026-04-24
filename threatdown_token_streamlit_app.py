import base64
import csv
import json
import os
from io import BytesIO
from io import StringIO
from typing import Optional, Tuple

import pandas as pd
import requests
import streamlit as st
from dotenv import load_dotenv


load_dotenv()


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
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=["id", "name", "online", "last_seen_at", "os_platform"])
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


def endpoint_to_selection_row(ep: dict) -> dict:
    machine = ep.get("machine", {}) if isinstance(ep.get("machine"), dict) else {}
    return {
        "migrar": False,
        "id": ep.get("id", ""),
        "machine_id": machine.get("id", ""),
        "name": ep.get("name") or ep.get("display_name", ""),
        "online": ep.get("online", ""),
        "last_seen_at": ep.get("last_seen_at", ""),
        "os_platform": ep.get("os_platform", ""),
    }


def build_migration_payload_variants(selected_rows: list, destination_account_token: str, command_name: str) -> list:
    machine_ids = [row.get("machine_id", "") for row in selected_rows if row.get("machine_id")]

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

tab_migration = st.tabs(["Migracion"])[0]

with tab_migration:
    with st.expander("Recomendación de seguridad", expanded=True):
        st.warning(
            "No pegues secretos reales en código fuente ni los subas a Git. "
            "Lo ideal es usar variables de entorno o un secret manager. "
            "Si ya expusiste un secret, rótalo antes de usar esta app."
        )

    prefill_client_id = os.getenv("THREATDOWN_CLIENT_ID", os.getenv("SOURCE_CLIENT_ID", ""))
    prefill_client_secret = os.getenv("THREATDOWN_CLIENT_SECRET", os.getenv("SOURCE_CLIENT_SECRET", ""))
    prefill_api_base_url = os.getenv("SOURCE_API_BASE_URL", API_BASE_URL)
    prefill_token_url = os.getenv("SOURCE_TOKEN_URL", TOKEN_URL)

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
        scope = st.text_input("Scope", value=DEFAULT_SCOPE)
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
    st.caption("GET de coleccion + paginacion automatica")

    with st.expander("Diagnóstico de ruta (si recibes 404)"):
        st.caption("Prueba rutas candidatas para descubrir cuál existe en tu tenant.")
        probe_token = st.text_input(
            "Access Token para diagnóstico",
            value=st.session_state.get("last_access_token", ""),
            type="password",
            key="probe_token",
        )
        probe_api_base_url = st.text_input(
            "API Base URL para diagnóstico",
            value=st.session_state.get("source_api_base_url", prefill_api_base_url),
            key="probe_api_base_url",
        )
        candidate_paths = st.text_area(
            "Rutas candidatas (una por línea)",
            value="\n".join(DEFAULT_CANDIDATE_PATHS),
            height=130,
        )
        if st.button("Probar rutas", use_container_width=True):
            if not probe_token.strip():
                st.error("Falta el Access Token para diagnóstico.")
            else:
                with st.spinner("Probando rutas..."):
                    probe_result = probe_paths(
                        probe_token.strip(),
                        candidate_paths,
                        api_base_url=probe_api_base_url.strip() or API_BASE_URL,
                    )
                st.dataframe(probe_result, use_container_width=True)
                valid = [r for r in probe_result if r.get("ok")]
                if valid:
                    st.success(f"Ruta(s) válidas encontradas: {', '.join([r['path'] for r in valid])}")
                else:
                    st.warning("Ninguna ruta candidata devolvió 2xx. Revisa documentación de tu tenant/API.")

    with st.form("list_endpoints_form"):
        list_access_token = st.text_input(
            "Access Token para listado",
            value=st.session_state.get("last_access_token", ""),
            placeholder="Pega aquí tu bearer token",
            type="password",
        )
        list_api_base_url = st.text_input(
            "API Base URL",
            value=st.session_state.get("source_api_base_url", prefill_api_base_url),
            help="Ejemplo: https://api.threatdown.com o https://api.malwarebytes.com",
        )
        endpoints_path = st.text_input(
            "Ruta de listado",
            value=DEFAULT_ENDPOINTS_PATH,
            placeholder="/nebula/v1/endpoints",
            help="Ruta relativa del listado. Si tu tenant usa otra, cámbiala aquí.",
        )
        request_method = st.selectbox("Método", options=["POST", "GET"], index=0)
        account_id = st.text_input(
            "Account ID (para POST)",
            value=DEFAULT_SOURCE_ACCOUNT_ID,
            help="Algunos tenants requieren header accountid para listar endpoints.",
        )
        page_size = st.number_input("Page size", min_value=1, max_value=500, value=200, step=1)
        max_pages = st.number_input("Max pages (0 = sin límite)", min_value=0, max_value=1000, value=0, step=1)
        list_submitted = st.form_submit_button("Listar endpoints", use_container_width=True)

    if list_submitted:
        if not list_access_token.strip():
            st.error("Falta el Access Token para listar endpoints.")
        else:
            with st.spinner("Consultando todos los endpoints..."):
                endpoints, list_detail = get_all_endpoints(
                    list_access_token.strip(),
                    endpoints_path=endpoints_path.strip() or DEFAULT_ENDPOINTS_PATH,
                    api_base_url=list_api_base_url.strip() or API_BASE_URL,
                    request_method=request_method,
                    account_id=account_id.strip(),
                    page_size=int(page_size),
                    max_pages=int(max_pages),
                )

            if endpoints is not None:
                st.success(f"Endpoints obtenidos: {len(endpoints)}")
                st.json(list_detail)
                st.session_state["listed_endpoints"] = endpoints

                if endpoints:
                    st.download_button(
                        "Descargar listado completo (CSV)",
                        data=endpoints_to_csv(endpoints),
                        file_name="endpoints.csv",
                        mime="text/csv",
                        use_container_width=True,
                    )
                else:
                    st.info("No se encontraron endpoints.")
            else:
                st.error("No se pudo listar endpoints.")
                st.json(list_detail)

    if st.session_state.get("listed_endpoints"):
        st.divider()
        st.subheader("3) Selección para migración")
        st.caption("Marca con checkbox los endpoints que quieres migrar.")

        selection_rows = [endpoint_to_selection_row(ep) for ep in st.session_state["listed_endpoints"]]

        with st.expander("Match desde Excel", expanded=True):
            st.caption(
                "Carga el Excel local o desde URL para hacer match contra los endpoints del origen."
            )

            # Detectar archivos Excel locales
            import glob as _glob
            local_xlsx = _glob.glob("*.xlsx") + _glob.glob("*.xls")

            tab_local, tab_url = st.tabs(["📁 Archivo local", "🌐 URL en la nube"])

            with tab_local:
                if local_xlsx:
                    selected_local = st.selectbox("Selecciona el archivo Excel", options=local_xlsx)
                    local_sheet = st.text_input("Hoja (opcional)", key="local_sheet", placeholder="Sheet1")
                    if st.button("Cargar Excel local", use_container_width=True, key="load_local_excel"):
                        try:
                            read_kwargs = {}
                            if local_sheet.strip():
                                read_kwargs["sheet_name"] = local_sheet.strip()
                            loaded_df = pd.read_excel(selected_local, **read_kwargs)
                            if isinstance(loaded_df, dict):
                                loaded_df = next(iter(loaded_df.values()))
                            loaded_df = loaded_df.rename(columns=lambda c: str(c).strip())
                            st.session_state["cloud_excel_df"] = loaded_df
                            st.session_state["matched_machine_ids"] = []
                            st.success(f"Excel cargado: {len(loaded_df)} filas, columnas: {list(loaded_df.columns)}")
                        except Exception as exc:
                            st.error(f"Error al cargar: {exc}")
                else:
                    st.info("No hay archivos .xlsx en el directorio actual.")

            with tab_url:
                with st.form("cloud_excel_form"):
                    excel_url = st.text_input(
                        "URL del Excel",
                        value=st.session_state.get("cloud_excel_url", ""),
                        placeholder="https://.../archivo.xlsx",
                    )
                    excel_sheet_name = st.text_input(
                        "Hoja (opcional)",
                        value=st.session_state.get("cloud_excel_sheet", ""),
                        placeholder="Sheet1",
                    )
                    load_excel_submitted = st.form_submit_button("Traer Excel desde la nube", use_container_width=True)

                if load_excel_submitted:
                    with st.spinner("Descargando y leyendo Excel..."):
                        loaded_df, excel_detail = load_cloud_excel(excel_url, sheet_name=excel_sheet_name)
                    if loaded_df is None:
                        st.error("No se pudo cargar el Excel.")
                        st.json(excel_detail)
                    else:
                        st.success(f"Excel cargado: {excel_detail['rows']} filas")
                        st.session_state["cloud_excel_df"] = loaded_df
                        st.session_state["cloud_excel_url"] = excel_url.strip()
                        st.session_state["cloud_excel_sheet"] = excel_sheet_name.strip()
                        st.session_state["matched_machine_ids"] = []
                        st.json(excel_detail)

            excel_df = st.session_state.get("cloud_excel_df")
            if isinstance(excel_df, pd.DataFrame):
                st.write("Vista previa del Excel")
                st.dataframe(excel_df.head(20), use_container_width=True)

                excel_columns = list(excel_df.columns)
                if not excel_columns:
                    st.warning("El Excel no tiene columnas para hacer match.")
                else:
                    suggested_column = None
                    preferred = [
                        "machine_id",
                        "machineid",
                        "endpoint_id",
                        "endpointid",
                        "id",
                        "host",
                        "hostname",
                        "host name",
                        "name",
                        "nombre",
                    ]
                    normalized_columns = {normalize_text(c): c for c in excel_columns}
                    for pc in preferred:
                        if pc in normalized_columns:
                            suggested_column = normalized_columns[pc]
                            break
                    if suggested_column is None:
                        suggested_column = excel_columns[0]

                    excel_match_column = st.selectbox(
                        "Columna del Excel para match",
                        options=excel_columns,
                        index=excel_columns.index(suggested_column),
                    )
                    source_match_field = st.selectbox(
                        "Comparar con campo en origen",
                        options=["machine_id", "id", "name"],
                        index=2 if normalize_text(excel_match_column) in ("host", "hostname", "name", "nombre") else 0,
                        help="Usa name cuando el Excel tenga nombres de equipo. Usa machine_id para IDs.",
                    )

                    if st.button("Aplicar match Excel vs origen", use_container_width=True):
                        matched_rows, match_detail = match_excel_rows_to_selection(
                            excel_df=excel_df,
                            selection_rows=selection_rows,
                            excel_match_column=excel_match_column,
                            source_match_field=source_match_field,
                        )
                        if match_detail.get("error"):
                            st.error(match_detail["error"])
                        else:
                            st.session_state["matched_machine_ids"] = [r.get("machine_id", "") for r in matched_rows]
                            st.session_state["last_matched_rows"] = matched_rows
                            st.session_state["last_match_detail"] = match_detail
                            st.session_state["last_excel_df"] = excel_df
                            total_excel = match_detail.get("excel_rows", len(excel_df))
                            matched_n = match_detail.get("matched", 0)
                            unmatched_n = match_detail.get("unmatched", 0)
                            st.success(f"✅ Match completado: {matched_n}/{total_excel} coincidencias ({unmatched_n} sin match)")
                            col_a, col_b = st.columns(2)
                            col_a.metric("Con match", matched_n)
                            col_b.metric("Sin match", unmatched_n)

                            if unmatched_n > 0:
                                matched_names = {normalize_text(r.get("name", "")) for r in matched_rows}
                                unmatched_list = [
                                    str(v) for v in excel_df[excel_match_column].tolist()
                                    if normalize_text(v) not in matched_names
                                ]
                                with st.expander(f"⚠️ Hosts sin match ({unmatched_n})", expanded=False):
                                    st.dataframe(pd.DataFrame({"host": unmatched_list}), use_container_width=True)

                    # Botón Guardar a SQLite (disponible si hay match previo)
                    if st.session_state.get("last_matched_rows") is not None:
                        st.divider()
                        if st.button("💾 Guardar resultados en SQLite (migration_tracking.db)", use_container_width=True, type="primary"):
                            try:
                                import sqlite3 as _sqlite3
                                _matched = st.session_state["last_matched_rows"]
                                _excel_df = st.session_state["last_excel_df"]
                                _detail = st.session_state["last_match_detail"]
                                _matched_names = {normalize_text(r.get("name", "")) for r in _matched}
                                _matched_by_name = {normalize_text(r.get("name", "")): r for r in _matched}

                                _db = "migration_tracking.db"
                                _conn = _sqlite3.connect(_db)
                                _cur = _conn.cursor()

                                _cur.execute("DROP TABLE IF EXISTS migration_hosts")
                                _cur.execute("""
                                    CREATE TABLE migration_hosts (
                                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                                        host_name TEXT NOT NULL,
                                        usuario TEXT,
                                        modelo TEXT,
                                        serial_number TEXT,
                                        machine_id TEXT,
                                        endpoint_id TEXT,
                                        match_status TEXT DEFAULT 'pending',
                                        migration_attempts INTEGER DEFAULT 0,
                                        last_migration_date TIMESTAMP,
                                        migration_status TEXT DEFAULT 'pending',
                                        error_message TEXT,
                                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                                    )
                                """)
                                _cur.execute("DROP TABLE IF EXISTS migration_attempts")
                                _cur.execute("""
                                    CREATE TABLE migration_attempts (
                                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                                        host_id INTEGER NOT NULL,
                                        attempt_number INTEGER,
                                        status TEXT,
                                        error_message TEXT,
                                        attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                        response_json TEXT,
                                        FOREIGN KEY(host_id) REFERENCES migration_hosts(id)
                                    )
                                """)

                                for _, row in _excel_df.iterrows():
                                    _host = str(row.get("Host", row.iloc[0]))
                                    _user = str(row.get("Nombre del Usuario", ""))
                                    _model = str(row.get("Modelo", ""))
                                    _sn = str(row.get("SN", ""))
                                    _norm = normalize_text(_host)
                                    if _norm in _matched_by_name:
                                        _ep = _matched_by_name[_norm]
                                        _cur.execute(
                                            "INSERT INTO migration_hosts (host_name, usuario, modelo, serial_number, machine_id, endpoint_id, match_status) VALUES (?,?,?,?,?,?,?)",
                                            (_host, _user, _model, _sn, _ep.get("machine_id",""), _ep.get("id",""), "matched")
                                        )
                                    else:
                                        _cur.execute(
                                            "INSERT INTO migration_hosts (host_name, usuario, modelo, serial_number, match_status) VALUES (?,?,?,?,?)",
                                            (_host, _user, _model, _sn, "not_found")
                                        )

                                _conn.commit()
                                _conn.close()
                                st.success(f"✅ Guardado en {_db} — {len(_excel_df)} hosts, {_detail.get('matched',0)} con match, {_detail.get('unmatched',0)} sin match")
                            except Exception as _exc:
                                st.error(f"Error al guardar: {_exc}")

        matched_machine_ids = set(st.session_state.get("matched_machine_ids", []))
        if matched_machine_ids:
            for row in selection_rows:
                if row.get("machine_id", "") in matched_machine_ids:
                    row["migrar"] = True

        selection_df = pd.DataFrame(selection_rows)

        edited_df = st.data_editor(
            selection_df,
            hide_index=True,
            use_container_width=True,
            column_config={
                "migrar": st.column_config.CheckboxColumn("Migrar", help="Selecciona endpoint para migración"),
                "id": st.column_config.TextColumn("Endpoint ID"),
                "machine_id": st.column_config.TextColumn("Machine ID"),
                "name": st.column_config.TextColumn("Nombre"),
                "online": st.column_config.TextColumn("Online"),
                "last_seen_at": st.column_config.TextColumn("Last seen"),
                "os_platform": st.column_config.TextColumn("OS"),
            },
            disabled=["id", "machine_id", "name", "online", "last_seen_at", "os_platform"],
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
                value=DEFAULT_SOURCE_ACCOUNT_ID,
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
                value=DEFAULT_SOURCE_ACCOUNT_ID,
            )
            destination_account_token = st.text_input(
                "Destination Account Token",
                value=DEFAULT_DESTINATION_ACCOUNT_TOKEN,
                type="password",
            )
            move_path = st.text_input("Jobs Path", value=DEFAULT_TARGET_MOVE_PATH)
            migration_command = st.text_input("Command", value=DEFAULT_MIGRATION_COMMAND)
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
            elif not destination_account_token.strip():
                st.error("Falta Destination Account Token.")
            else:
                selected_batches = chunk_rows(selected_rows, int(batch_size))

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
                        destination_account_token=destination_account_token.strip(),
                        command_name=migration_command.strip() or DEFAULT_MIGRATION_COMMAND,
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
                            destination_account_token=destination_account_token.strip(),
                            command_name=migration_command.strip() or DEFAULT_MIGRATION_COMMAND,
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
                                "machine_ids": [r.get("machine_id", "") for r in batch_rows if r.get("machine_id")],
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
