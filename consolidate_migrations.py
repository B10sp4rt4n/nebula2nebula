#!/usr/bin/env python3
"""
Script para hacer matching de hosts con endpoints y consolidar en SQLite local
"""
import sys
sys.path.insert(0, '/workspaces/nebula2nebula')

import os
import sqlite3
import json
import pandas as pd
from pathlib import Path
from dotenv import load_dotenv
from threatdown_token_streamlit_app import normalize_text, match_excel_rows_to_selection
import warnings
warnings.filterwarnings('ignore')

load_dotenv()

print("=" * 80)
print("🚀 MIGRACIÓN NEBULA - ANÁLISIS Y CONSOLIDACIÓN COMPLETO")
print("=" * 80)

# ============================================================================
# 1. CARGAR ENDPOINTS
# ============================================================================
print("\n📡 PASO 1: Cargando endpoints disponibles...")

all_endpoints = None
endpoints_source = None

# Intentar cargar desde archivos locales
endpoints_json = Path('/workspaces/nebula2nebula/endpoints_origin.json')
endpoints_csv = Path('/workspaces/nebula2nebula/endpoints_origin.csv')

if endpoints_json.exists():
    print(f"   Cargando desde: {endpoints_json}")
    with open(endpoints_json, 'r') as f:
        all_endpoints = json.load(f)
    endpoints_source = "endpoints_origin.json"
    
elif endpoints_csv.exists():
    print(f"   Cargando desde: {endpoints_csv}")
    df_endpoints = pd.read_csv(endpoints_csv)
    all_endpoints = df_endpoints.to_dict('records')
    endpoints_source = "endpoints_origin.csv"
    
else:
    print("   ⚠️  No se encontraron endpoints locales")
    print("   Intenta exportarlos usando: python3 export_endpoints.py")
    all_endpoints = []
    endpoints_source = "none"

if all_endpoints:
    print(f"✅ Endpoints cargados: {len(all_endpoints)}")
    print(f"   Fuente: {endpoints_source}")
else:
    print("⚠️  Sin endpoints disponibles - los hosts se marcarán como 'pendiente de validación'")

# ============================================================================
# 2. CARGAR EXCEL CON LOS HOSTS A MIGRAR
# ============================================================================
print("\n📄 PASO 2: Cargando Excel con hosts a migrar...")
excel_file = "Hosts a migrar - MalwareBytes TXAT.xlsx"
try:
    excel_df = pd.read_excel(excel_file)
    total_excel_hosts = len(excel_df)
    print(f"✅ Excel cargado: {total_excel_hosts} hosts")
    print(f"   Columnas: {list(excel_df.columns)}")
except Exception as e:
    print(f"❌ Error cargando Excel: {e}")
    sys.exit(1)

# ============================================================================
# 3. HACER MATCHING (SI HAY ENDPOINTS)
# ============================================================================
print("\n🔍 PASO 3: Haciendo matching...")

matched_rows = []
match_stats = {'matched': 0, 'unmatched': total_excel_hosts}

if all_endpoints and len(all_endpoints) > 0:
    try:
        matched_rows, match_stats = match_excel_rows_to_selection(
            excel_df=excel_df,
            selection_rows=all_endpoints,
            excel_match_column='Host',
            source_match_field='name'
        )
        print(f"✅ Matching completado:")
        print(f"   - Coincidencias: {match_stats.get('matched', 0)}")
        print(f"   - Sin coincidencia: {match_stats.get('unmatched', 0)}")
    except Exception as e:
        print(f"⚠️  Error en matching: {e}")
        print("   Continuando sin matching...")
        matched_rows = []
else:
    print("⚠️  No hay endpoints para hacer matching")
    print("   Los hosts se marcarán como 'pendiente de validación'")

# ============================================================================
# 4. CREAR TABLA SQLite
# ============================================================================
print("\n💾 PASO 4: Creando base de datos SQLite...")

DB_FILE = '/workspaces/nebula2nebula/migration_tracking.db'
conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()

# Crear tabla principal
cursor.execute('DROP TABLE IF EXISTS migration_hosts')
cursor.execute('''
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
''')

# Crear tabla de intentos
cursor.execute('DROP TABLE IF EXISTS migration_attempts')
cursor.execute('''
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
''')

print(f"✅ Tablas creadas")

# ============================================================================
# 5. INSERTAR DATOS
# ============================================================================
print("\n📊 PASO 5: Insertando datos en la base de datos...")

matched_by_name = {normalize_text(ep.get('name', '')): ep for ep in matched_rows if ep.get('name')}

matched_hosts_count = 0
unmatched_hosts = []

for idx, row in excel_df.iterrows():
    host_name = row.get('Host', 'UNKNOWN')
    usuario = row.get('Nombre del Usuario', '')
    modelo = row.get('Modelo', '')
    sn = row.get('SN', '')
    
    match_found = False
    endpoint_info = None
    
    # Buscar coincidencia
    if matched_rows:
        normalized_host = normalize_text(host_name)
        if normalized_host in matched_by_name:
            endpoint_info = matched_by_name[normalized_host]
            match_found = True
            matched_hosts_count += 1
    
    if match_found and endpoint_info:
        cursor.execute('''
            INSERT INTO migration_hosts 
            (host_name, usuario, modelo, serial_number, machine_id, endpoint_id, match_status, migration_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            host_name,
            usuario,
            modelo,
            sn,
            endpoint_info.get('machine_id', ''),
            endpoint_info.get('id', ''),
            'matched',
            'pending'
        ))
    else:
        match_status = 'not_found' if all_endpoints else 'pending_validation'
        migration_status = 'pending'
        
        unmatched_hosts.append({
            'host': host_name,
            'usuario': usuario,
            'modelo': modelo,
            'sn': sn,
            'status': match_status
        })
        
        cursor.execute('''
            INSERT INTO migration_hosts 
            (host_name, usuario, modelo, serial_number, match_status, migration_status)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            host_name,
            usuario,
            modelo,
            sn,
            match_status,
            migration_status
        ))

conn.commit()
print(f"✅ {total_excel_hosts} hosts insertados en la base de datos")

# ============================================================================
# 6. MOSTRAR RESUMEN
# ============================================================================
print("\n" + "=" * 80)
print("📋 RESUMEN DEL ANÁLISIS")
print("=" * 80)

cursor.execute('SELECT COUNT(*) FROM migration_hosts')
total_hosts = cursor.fetchone()[0]

cursor.execute('SELECT COUNT(*) FROM migration_hosts WHERE match_status = "matched"')
hosts_matched = cursor.fetchone()[0]

cursor.execute('SELECT COUNT(*) FROM migration_hosts WHERE match_status != "matched"')
hosts_not_matched = cursor.fetchone()[0]

print(f"\n📊 ESTADÍSTICAS GENERALES:")
print(f"   • Total hosts en Excel: {total_excel_hosts}")
print(f"   • Endpoints disponibles en origen: {len(all_endpoints) if all_endpoints else 'N/A'}")
print(f"   • Hosts listos para migrar (CON MATCH): {hosts_matched}")
print(f"   • Hosts sin match: {hosts_not_matched}")

if total_excel_hosts > 0:
    tasa = (hosts_matched / total_excel_hosts * 100)
    print(f"   • Tasa de coincidencia: {tasa:.1f}%")

print(f"\n💾 Base de datos: {DB_FILE}")
print(f"   • Tabla: migration_hosts")
print(f"   • Tabla: migration_attempts (para rastrear intentos de migración)")

if hosts_matched > 0:
    print(f"\n✅ HOSTS LISTOS PARA MIGRAR ({hosts_matched}):")
    cursor.execute('''
        SELECT id, host_name, usuario, machine_id, endpoint_id
        FROM migration_hosts 
        WHERE match_status = "matched"
        ORDER BY id
        LIMIT 15
    ''')
    for row in cursor.fetchall():
        print(f"   {row[0]:3} | {row[1]:20} | {row[2]:25} | {row[3][:8] if row[3] else 'N/A'}...")
    
    if hosts_matched > 15:
        print(f"   ... y {hosts_matched - 15} más")

if hosts_not_matched > 0:
    print(f"\n⚠️  HOSTS SIN MATCH ({hosts_not_matched}):")
    status_summary = {}
    cursor.execute('SELECT match_status, COUNT(*) FROM migration_hosts WHERE match_status != "matched" GROUP BY match_status')
    for status, count in cursor.fetchall():
        status_summary[status] = count
        print(f"   • {status}: {count}")

# ============================================================================
# 7. EXPORTAR REPORTES
# ============================================================================
print("\n📁 Exportando reportes...")

# Reporte de coincidencias
cursor.execute('''
    SELECT id, host_name, usuario, machine_id, endpoint_id, match_status, created_at
    FROM migration_hosts
    WHERE match_status = "matched"
    ORDER BY id
''')

matched_report = {
    'summary': {
        'total_matched': hosts_matched,
        'total_excel': total_excel_hosts,
        'endpoints_available': len(all_endpoints) if all_endpoints else None,
        'endpoints_source': endpoints_source,
        'match_percentage': round(hosts_matched / total_excel_hosts * 100, 1) if total_excel_hosts > 0 else 0
    },
    'hosts': [
        {
            'id': row[0],
            'host_name': row[1],
            'usuario': row[2],
            'machine_id': row[3],
            'endpoint_id': row[4],
            'status': row[5],
            'created_at': row[6]
        }
        for row in cursor.fetchall()
    ]
}

with open('/workspaces/nebula2nebula/migration_report_matched.json', 'w') as f:
    json.dump(matched_report, f, indent=2)
print(f"✅ Reporte de coincidencias: migration_report_matched.json")

# Reporte de no coincidencias
report_unmatched = {
    'summary': {
        'total_unmatched': hosts_not_matched,
        'reasons': status_summary if hosts_not_matched > 0 else {}
    },
    'hosts': unmatched_hosts
}

with open('/workspaces/nebula2nebula/migration_report_unmatched.json', 'w') as f:
    json.dump(report_unmatched, f, indent=2)
print(f"✅ Reporte de no coincidencias: migration_report_unmatched.json")

# Reporte CSV completo
cursor.execute('''
    SELECT id, host_name, usuario, modelo, serial_number, machine_id, endpoint_id, 
           match_status, migration_attempts, migration_status, created_at
    FROM migration_hosts
    ORDER BY id
''')

all_data = cursor.fetchall()
df_export = pd.DataFrame(all_data, columns=[
    'id', 'host_name', 'usuario', 'modelo', 'serial_number', 'machine_id', 
    'endpoint_id', 'match_status', 'migration_attempts', 'migration_status', 'created_at'
])

df_export.to_csv('/workspaces/nebula2nebula/migration_hosts_complete.csv', index=False)
print(f"✅ Reporte CSV completo: migration_hosts_complete.csv")

conn.close()

print("\n" + "=" * 80)
print("✨ CONSOLIDACIÓN COMPLETADA")
print("=" * 80)

print(f"\n📌 PRÓXIMOS PASOS:")
print(f"   1. Obtener endpoints desde la consola origen")
print(f"   2. Si aún no tienes credentials válidas, updatelas en .env")
print(f"   3. Ejecuta: python3 export_endpoints.py")
print(f"   4. Luego: python3 consolidate_migrations.py (este script)")
print(f"\n📂 Archivos generados:")
print(f"   • migration_tracking.db - Base de datos SQLite")
print(f"   • migration_report_matched.json - Hosts listos para migrar")
print(f"   • migration_report_unmatched.json - Hosts sin match")
print(f"   • migration_hosts_complete.csv - Reporte completo")
