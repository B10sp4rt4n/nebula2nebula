#!/usr/bin/env python3
"""
Script para hacer matching entre hosts y endpoints,
actualizando la BD con los resultados
"""
import sys
sys.path.insert(0, '/workspaces/nebula2nebula')

import sqlite3
import json
from pathlib import Path
import pandas as pd
from threatdown_token_streamlit_app import normalize_text, match_excel_rows_to_selection
import warnings
warnings.filterwarnings('ignore')

print("=" * 80)
print("🔍 SCRIPT DE MATCHING - HOSTS vs ENDPOINTS")
print("=" * 80)

# ============================================================================
# 1. CARGAR ENDPOINTS
# ============================================================================
print("\n📡 PASO 1: Buscando endpoints...")

all_endpoints = None
endpoints_file = None

endpoints_json = Path('/workspaces/nebula2nebula/endpoints_origin.json')
endpoints_csv = Path('/workspaces/nebula2nebula/endpoints_origin.csv')

if endpoints_json.exists():
    print(f"   Cargando desde: {endpoints_json.name}")
    with open(endpoints_json, 'r') as f:
        all_endpoints = json.load(f)
    endpoints_file = "endpoints_origin.json"
    
elif endpoints_csv.exists():
    print(f"   Cargando desde: {endpoints_csv.name}")
    df = pd.read_csv(endpoints_csv)
    all_endpoints = df.to_dict('records')
    endpoints_file = "endpoints_origin.csv"

if not all_endpoints:
    print("❌ No se encontraron endpoints.")
    print("   Primero debes ejecutar: python3 export_endpoints.py")
    sys.exit(1)

print(f"✅ Endpoints cargados: {len(all_endpoints)}")

# ============================================================================
# 2. CARGAR HOSTS DE LA BD
# ============================================================================
print("\n📋 PASO 2: Cargando hosts desde BD...")

DB_FILE = '/workspaces/nebula2nebula/migration_tracking.db'
conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()

cursor.execute('SELECT COUNT(*) FROM migration_hosts')
total_hosts = cursor.fetchone()[0]
print(f"✅ Hosts en BD: {total_hosts}")

# ============================================================================
# 3. HACER MATCHING
# ============================================================================
print("\n🔍 PASO 3: Haciendo matching...")

# Crear índice de endpoints por nombre normalizado
endpoint_by_name = {}
for ep in all_endpoints:
    name = ep.get('name', '')
    if name:
        normalized = normalize_text(name)
        endpoint_by_name[normalized] = ep

print(f"   Índice de endpoints creado: {len(endpoint_by_name)} nombres únicos")

# Hacer matching
cursor.execute('SELECT id, host_name FROM migration_hosts ORDER BY id')
hosts_to_match = cursor.fetchall()

matched_count = 0
updated_count = 0

for host_id, host_name in hosts_to_match:
    normalized_host = normalize_text(host_name)
    
    if normalized_host in endpoint_by_name:
        endpoint = endpoint_by_name[normalized_host]
        
        cursor.execute('''
            UPDATE migration_hosts
            SET 
                match_status = "matched",
                machine_id = ?,
                endpoint_id = ?,
                migration_status = "pending"
            WHERE id = ?
        ''', (
            endpoint.get('machine_id', ''),
            endpoint.get('id', ''),
            host_id
        ))
        
        matched_count += 1
        updated_count += 1

conn.commit()

print(f"✅ Matching completado:")
print(f"   • Hosts coincidentes: {matched_count}")
print(f"   • Hosts sin match: {total_hosts - matched_count}")
print(f"   • Porcentaje: {(matched_count/total_hosts*100):.1f}%")

# ============================================================================
# 4. GUARDAR ENDPOINTS EN BD
# ============================================================================
print("\n💾 PASO 4: Importando endpoints a la BD...")

cursor.execute('DELETE FROM endpoints_available')

for endpoint in all_endpoints:
    cursor.execute('''
        INSERT OR IGNORE INTO endpoints_available
        (machine_id, endpoint_id, name, os_platform, online, last_seen)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (
        endpoint.get('machine_id', ''),
        endpoint.get('id', ''),
        endpoint.get('name', ''),
        endpoint.get('os_platform', ''),
        endpoint.get('online', False),
        endpoint.get('last_seen_at', '')
    ))

conn.commit()

cursor.execute('SELECT COUNT(*) FROM endpoints_available')
endpoints_count = cursor.fetchone()[0]
print(f"✅ Endpoints guardados: {endpoints_count}")

# ============================================================================
# 5. ACTUALIZAR CONFIGURACIÓN
# ============================================================================
print("\n⚙️  PASO 5: Actualizando configuración...")

cursor.execute('DELETE FROM migration_config')
cursor.execute('''
    INSERT INTO migration_config
    (total_endpoints_available, total_hosts_to_migrate, endpoints_source, last_matching_date)
    VALUES (?, ?, ?, CURRENT_TIMESTAMP)
''', (
    len(all_endpoints),
    total_hosts,
    endpoints_file
))

conn.commit()
print(f"✅ Configuración guardada")

# ============================================================================
# 6. ACTUALIZAR ESTADÍSTICAS
# ============================================================================
print("\n📊 PASO 6: Actualizando estadísticas...")

cursor.execute('SELECT COUNT(*) FROM migration_hosts WHERE match_status = "matched"')
matched_total = cursor.fetchone()[0]

cursor.execute('SELECT COUNT(*) FROM migration_hosts WHERE match_status = "not_found"')
not_found_total = cursor.fetchone()[0]

cursor.execute('SELECT COUNT(*) FROM migration_hosts WHERE migration_status = "pending"')
pending_total = cursor.fetchone()[0]

match_percentage = (matched_total / total_hosts * 100) if total_hosts > 0 else 0

cursor.execute('''
    INSERT INTO migration_statistics
    (total_available, total_to_migrate, matched, not_matched, pending_migration, match_percentage)
    VALUES (?, ?, ?, ?, ?, ?)
''', (
    len(all_endpoints),
    total_hosts,
    matched_total,
    total_hosts - matched_total,
    pending_total,
    match_percentage
))

conn.commit()
print(f"✅ Estadísticas actualizadas")

# ============================================================================
# 7. RESUMEN FINAL
# ============================================================================
print("\n" + "=" * 80)
print("📋 RESUMEN DEL MATCHING")
print("=" * 80)

print(f"\n📊 ESTADÍSTICAS:")
print(f"   • Endpoints disponibles en origen: {len(all_endpoints)}")
print(f"   • Hosts en Excel: {total_hosts}")
print(f"   • Hosts con MATCH: {matched_total}")
print(f"   • Hosts sin match: {total_hosts - matched_total}")
print(f"   • Tasa de coincidencia: {match_percentage:.1f}%")

# Mostrar hosts matched
print(f"\n✅ PRIMEROS 10 HOSTS CON MATCH:")
cursor.execute('''
    SELECT id, host_name, usuario, machine_id
    FROM migration_hosts
    WHERE match_status = "matched"
    ORDER BY id
    LIMIT 10
''')

for row in cursor.fetchall():
    print(f"   {row[0]:3} | {row[1]:20} | {row[2]:30} | {row[3][:8]}...")

matched_remaining = matched_total - 10
if matched_remaining > 0:
    print(f"   ... y {matched_remaining} más")

# Mostrar hosts no matched
if total_hosts - matched_total > 0:
    print(f"\n⚠️  PRIMERS 10 HOSTS SIN MATCH:")
    cursor.execute('''
        SELECT id, host_name, usuario
        FROM migration_hosts
        WHERE match_status != "matched"
        ORDER BY id
        LIMIT 10
    ''')
    
    for row in cursor.fetchall():
        print(f"   {row[0]:3} | {row[1]:20} | {row[2]:30}")
    
    remaining = total_hosts - matched_total - 10
    if remaining > 0:
        print(f"   ... y {remaining} más")

print("\n" + "=" * 80)
print("✨ MATCHING COMPLETADO")
print("=" * 80)

print(f"\n💾 Base de datos: migration_tracking.db")
print(f"   • migration_hosts: {total_hosts} registros")
print(f"   • endpoints_available: {endpoints_count} registros")
print(f"   • migration_statistics: 2 registros")

conn.close()

print(f"\n✅ Proceso completado exitosamente!")
