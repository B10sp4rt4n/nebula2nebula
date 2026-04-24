#!/usr/bin/env python3
import os
import sys
sys.path.insert(0, '/workspaces/nebula2nebula')

from threatdown_token_streamlit_app import get_token, get_all_endpoints, normalize_text, build_match_indexes, match_excel_rows_to_selection
import pandas as pd
from dotenv import load_dotenv
import warnings
warnings.filterwarnings('ignore')

load_dotenv()

# Obtener endpoints del origen
print("📡 Obteniendo endpoints del origen...")
token = get_token(
    os.getenv('SOURCE_TOKEN_URL'),
    os.getenv('SOURCE_CLIENT_ID'),
    os.getenv('SOURCE_CLIENT_SECRET'),
    os.getenv('SOURCE_SCOPE')
)

all_endpoints, stats_resp = get_all_endpoints(
    token,  # access_token
    os.getenv('SOURCE_ENDPOINTS_PATH'),  # endpoints_path
    os.getenv('SOURCE_API_BASE_URL'),    # api_base_url
    "POST",                              # request_method
    os.getenv('SOURCE_ACCOUNT_ID'),      # account_id
    int(os.getenv('PAGE_SIZE', 200)),    # page_size
    int(os.getenv('MAX_PAGES', 0))       # max_pages
)

if all_endpoints is None:
    print(f"❌ Error obteniendo endpoints!")
    print(f"Detalles del error: {stats_resp}")
    sys.exit(1)

print(f"✅ Total endpoints encontrados: {len(all_endpoints)}")

# Cargar Excel
excel_file = "Hosts a migrar - MalwareBytes TXAT.xlsx"
excel_df = pd.read_excel(excel_file)
print(f"\n✅ Excel cargado: {excel_df.shape[0]} filas, {excel_df.shape[1]} columnas")
print(f"   Columnas: {list(excel_df.columns)}")

print(f"\n📋 Primeras 5 filas del Excel:")
print(excel_df.head(5).to_string())

# Hacer matching con la primera columna
first_col = excel_df.columns[0]
print(f"\n🔍 Haciendo matching con columna: '{first_col}'")

matched_rows, stats = match_excel_rows_to_selection(
    excel_df=excel_df,
    selection_rows=all_endpoints,
    excel_match_column=first_col,
    source_match_field='name'
)

print(f"\n{'='*70}")
print(f"✨ RESULTADOS FINALES")
print(f"{'='*70}")
print(f"📊 Total endpoints a migrar: {stats['matched_count']}")
print(f"📊 Sin coincidencia: {stats['unmatched_count']}")
print(f"📊 Tasa de coincidencia: {stats['match_percentage']:.1f}%")

if matched_rows:
    print(f"\n🎯 Primeros 5 endpoints que HACEN MATCH:")
    for i, ep in enumerate(matched_rows[:5], 1):
        print(f"   {i}. {ep.get('name', 'N/A')} (ID: {ep.get('machine_id', 'N/A')[:8]}...)")

print(f"\n{'='*70}")
