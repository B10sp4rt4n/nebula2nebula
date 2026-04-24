#!/usr/bin/env python3
import sys
sys.path.insert(0, '/workspaces/nebula2nebula')

from threatdown_token_streamlit_app import normalize_text, build_match_indexes, match_excel_rows_to_selection
import pandas as pd

# Crear datos de ejemplo - Excel con nombres de máquinas
excel_data = {
    'Hostname': [
        'DESKTOP-ABC123',
        'LAPTOP-XYZ789',
        'SERVER-PROD-01',
        'WORKSTATION-JOHN',
        'TABLET-MOBILE-IOS',
        'PC-LEGACY-OLD'
    ]
}

excel_df = pd.DataFrame(excel_data)

# Crear datos de ejemplo - Endpoints del origen
origin_endpoints = [
    {'machine_id': 'mach-001', 'id': 'ep-001', 'name': 'DESKTOP-ABC123'},
    {'machine_id': 'mach-002', 'id': 'ep-002', 'name': 'LAPTOP-XYZ789'},
    {'machine_id': 'mach-003', 'id': 'ep-003', 'name': 'SERVER-PROD-01'},
    {'machine_id': 'mach-004', 'id': 'ep-004', 'name': 'WORKSTATION-JOHN'},
    {'machine_id': 'mach-005', 'id': 'ep-005', 'name': 'DESKTOP-ANOTHER'},  # No está en Excel
    {'machine_id': 'mach-006', 'id': 'ep-006', 'name': 'SERVER-PROD-02'},    # No está en Excel
    {'machine_id': 'mach-007', 'id': 'ep-007', 'name': 'TABLET-MOBILE-IOS'},
    {'machine_id': 'mach-008', 'id': 'ep-008', 'name': 'PC-LEGACY-OLD'},
]

print("=" * 70)
print("🧪 TEST DE MATCHING - EXCEL vs. ENDPOINTS")
print("=" * 70)

print(f"\n📄 Excel de ejemplo:")
print(f"   Filas: {len(excel_df)}")
print(f"   Columnas: {list(excel_df.columns)}")
print(f"\n   Contenido:")
print(excel_df.to_string(index=False))

print(f"\n📡 Endpoints de origen (simulados):")
print(f"   Total: {len(origin_endpoints)}")
print(f"\n   Contenido:")
for i, ep in enumerate(origin_endpoints, 1):
    print(f"   {i}. {ep['name']} (machine_id: {ep['machine_id']})")

# Ejecutar matching
print(f"\n🔍 Ejecutando matching (columna: 'Hostname' vs campo: 'name')...")
matched_rows, stats = match_excel_rows_to_selection(
    excel_df=excel_df,
    selection_rows=origin_endpoints,
    excel_match_column='Hostname',
    source_match_field='name'
)

print(f"\n{'='*70}")
print(f"✨ RESULTADOS DEL MATCHING")
print(f"{'='*70}")
print(f"📊 Total endpoints a migrar (MATCH): {stats['matched']}")
print(f"📊 Endpoints sin coincidencia: {stats['unmatched']}")
match_percentage = (stats['matched'] / stats['excel_rows'] * 100) if stats['excel_rows'] > 0 else 0
print(f"📊 Tasa de coincidencia: {match_percentage:.1f}%")

print(f"\n🎯 Endpoints que HACEN MATCH:")
if matched_rows:
    for i, ep in enumerate(matched_rows, 1):
        print(f"   {i}. {ep.get('name', 'N/A'):30} (machine_id: {ep.get('machine_id', 'N/A')})")
else:
    print("   ❌ Ninguno")

print(f"\n{'='*70}")

# Verificar que el résultado es correcto
expected_matches = 6  # DESKTOP-ABC123, LAPTOP-XYZ789, SERVER-PROD-01, WORKSTATION-JOHN, TABLET-MOBILE-IOS, PC-LEGACY-OLD
if stats['matched'] == expected_matches:
    print(f"✅ TEST OK - Matching funcionando correctamente!")
else:
    print(f"❌ TEST FALLIDO - Esperaba {expected_matches} matches, pero obtuvo {stats['matched']}")
    sys.exit(1)
