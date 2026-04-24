#!/usr/bin/env python3
"""
Crear tablas adicionales en SQLite para rastrear
- Endpoints disponibles
- Intentos de migración
- Resultados de migración
"""

import sqlite3

DB_FILE = '/workspaces/nebula2nebula/migration_tracking.db'
conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()

print("Creando tablas adicionales en SQLite...")

# Tabla endpoints
cursor.execute('DROP TABLE IF EXISTS endpoints_available')
cursor.execute('''
    CREATE TABLE endpoints_available (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        machine_id TEXT UNIQUE,
        endpoint_id TEXT,
        name TEXT,
        os_platform TEXT,
        online BOOLEAN,
        last_seen TIMESTAMP,
        imported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
''')

# Tabla de configuración de migración
cursor.execute('DROP TABLE IF EXISTS migration_config')
cursor.execute('''
    CREATE TABLE migration_config (
        id INTEGER PRIMARY KEY,
        total_endpoints_available INTEGER,
        total_hosts_to_migrate INTEGER,
        last_matching_date TIMESTAMP,
        endpoints_source TEXT,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
''')

# Tabla de estadísticas
cursor.execute('DROP TABLE IF EXISTS migration_statistics')
cursor.execute('''
    CREATE TABLE migration_statistics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        report_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        total_available INTEGER,
        total_to_migrate INTEGER,
        matched INTEGER,
        not_matched INTEGER,
        pending_migration INTEGER,
        completed_migration INTEGER,
        failed_migration INTEGER,
        match_percentage REAL
    )
''')

conn.commit()

# Insertar estadísticas actuales
cursor.execute('SELECT COUNT(*) FROM migration_hosts')
total_hosts = cursor.fetchone()[0]

cursor.execute('SELECT COUNT(*) FROM migration_hosts WHERE match_status = "matched"')
matched = cursor.fetchone()[0]

not_matched = total_hosts - matched

cursor.execute('''
    INSERT INTO migration_statistics 
    (total_available, total_to_migrate, matched, not_matched, pending_migration, completed_migration, failed_migration, match_percentage)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
''', (None, total_hosts, matched, not_matched, total_hosts - matched, 0, 0, 0.0))

conn.commit()

print(f"✅ Tablas adicionales creadas:")
print(f"   • endpoints_available")
print(f"   • migration_config")
print(f"   • migration_statistics")
print(f"\n📊 Estadísticas guardadas")

conn.close()
