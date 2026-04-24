#!/usr/bin/env python3
"""
Generar reporte HTML interactivo de la migración
"""
import sqlite3
import json
from datetime import datetime

DB_FILE = '/workspaces/nebula2nebula/migration_tracking.db'

html_content = """
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Migración Nebula</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .content {
            padding: 40px;
        }
        
        .row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .card {
            background: #f8f9fa;
            border-left: 4px solid #667eea;
            padding: 20px;
            border-radius: 8px;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
        }
        
        .card h3 {
            color: #667eea;
            font-size: 0.9em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
        }
        
        .card .number {
            font-size: 2em;
            font-weight: bold;
            color: #333;
        }
        
        .card .percentage {
            font-size: 0.9em;
            color: #666;
            margin-top: 5px;
        }
        
        .status-matched {
            border-left-color: #28a745;
        }
        
        .status-pending {
            border-left-color: #ffc107;
        }
        
        .status-failed {
            border-left-color: #dc3545;
        }
        
        .section {
            margin-bottom: 40px;
        }
        
        .section h2 {
            color: #333;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        
        table thead {
            background: #f8f9fa;
        }
        
        table th {
            text-align: left;
            padding: 12px;
            color: #333;
            font-weight: 600;
            border-bottom: 2px solid #ddd;
        }
        
        table td {
            padding: 12px;
            border-bottom: 1px solid #ddd;
        }
        
        table tr:hover {
            background: #f8f9fa;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 600;
        }
        
        .badge-matched {
            background: #d4edda;
            color: #155724;
        }
        
        .badge-pending {
            background: #fff3cd;
            color: #856404;
        }
        
        .badge-not-found {
            background: #f8d7da;
            color: #721c24;
        }
        
        .progress-bar {
            background: #e9ecef;
            height: 8px;
            border-radius: 4px;
            overflow: hidden;
            margin-top: 10px;
        }
        
        .progress-fill {
            background: linear-gradient(90deg, #667eea, #764ba2);
            height: 100%;
            transition: width 0.3s;
        }
        
        .footer {
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            font-size: 0.9em;
            border-top: 1px solid #ddd;
        }
        
        .alert {
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 4px;
        }
        
        .alert-info {
            background: #d1ecf1;
            border: 1px solid #bee5eb;
            color: #0c5460;
        }
        
        .alert-warning {
            background: #fff3cd;
            border: 1px solid #ffeeba;
            color: #856404;
        }
        
        @media (max-width: 768px) {
            .header h1 {
                font-size: 1.8em;
            }
            
            .row {
                grid-template-columns: 1fr;
            }
            
            table {
                font-size: 0.9em;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 Reporte de Migración Nebula</h1>
            <p>Estado Actual de la Migración de Hosts</p>
        </div>
        
        <div class="content">
"""

# Conectar a BD y obtener datos
conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()

# Estadísticas generales
cursor.execute('SELECT COUNT(*) FROM migration_hosts')
total_hosts = cursor.fetchone()[0]

cursor.execute('SELECT COUNT(*) FROM migration_hosts WHERE match_status = "matched"')
matched = cursor.fetchone()[0]

cursor.execute('SELECT COUNT(*) FROM migration_hosts WHERE match_status = "pending_validation"')
pending = cursor.fetchone()[0]

cursor.execute('SELECT COUNT(*) FROM migration_hosts WHERE match_status = "not_found"')
not_found = cursor.fetchone()[0]

cursor.execute('SELECT COUNT(*) FROM endpoints_available')
endpoints_count = cursor.fetchone()[0]

percentage = (matched / total_hosts * 100) if total_hosts > 0 else 0

# Añadir estadísticas
html_content += f"""
            <div class="alert alert-info">
                <strong>ℹ️ Información:</strong> Este reporte muestra el estado actual de la migración de {total_hosts} hosts desde Nebula.
            </div>
            
            <div class="row">
                <div class="card status-matched">
                    <h3>✅ Hosts Listos (MATCH)</h3>
                    <div class="number">{matched}</div>
                    <div class="percentage">de {total_hosts} hosts</div>
                </div>
                
                <div class="card status-pending">
                    <h3>⏳ Pendiente de Validación</h3>
                    <div class="number">{pending}</div>
                    <div class="percentage">esperando endpoints</div>
                </div>
                
                <div class="card status-failed">
                    <h3>❌ No Encontrados</h3>
                    <div class="number">{not_found}</div>
                    <div class="percentage">sin equivalente</div>
                </div>
                
                <div class="card">
                    <h3>📡 Endpoints Disponibles</h3>
                    <div class="number">{endpoints_count}</div>
                    <div class="percentage">en origen</div>
                </div>
            </div>
            
            <div class="section">
                <h2>📈 Tasa de Coincidencia</h2>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: {percentage}%"></div>
                </div>
                <p style="text-align: center; margin-top: 10px; color: #666; font-weight: 600;">
                    {percentage:.1f}% completado ({matched} de {total_hosts} hosts)
                </p>
            </div>
            
            <div class="section">
                <h2>📋 Hosts Listos para Migrar (Primeros 20)</h2>
"""

# Tabla de hosts matched
cursor.execute('''
    SELECT id, host_name, usuario, machine_id, migration_attempts, migration_status
    FROM migration_hosts
    WHERE match_status = "matched"
    ORDER BY id
    LIMIT 20
''')

matched_hosts = cursor.fetchall()

if matched_hosts:
    html_content += """
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Host</th>
                            <th>Usuario</th>
                            <th>Machine ID</th>
                            <th>Intentos</th>
                            <th>Estado</th>
                        </tr>
                    </thead>
                    <tbody>
    """
    
    for host in matched_hosts:
        html_content += f"""
                        <tr>
                            <td><strong>#{host[0]}</strong></td>
                            <td>{host[1]}</td>
                            <td>{host[2]}</td>
                            <td><code>{host[3][:12] if host[3] else 'N/A'}...</code></td>
                            <td>{host[4]}</td>
                            <td><span class="badge badge-{host[5]}">{host[5]}</span></td>
                        </tr>
        """
    
    html_content += """
                    </tbody>
                </table>
    """
else:
    html_content += '<p style="color: #999;">No hay hosts matched aún. Ejecuta match_endpoints_with_hosts.py</p>'

html_content += """
            </div>
            
            <div class="section">
                <h2>⚠️ Hosts Pendiente de Validación (Primeros 20)</h2>
"""

cursor.execute('''
    SELECT id, host_name, usuario, match_status
    FROM migration_hosts
    WHERE match_status != "matched"
    ORDER BY id
    LIMIT 20
''')

other_hosts = cursor.fetchall()

if other_hosts:
    html_content += """
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Host</th>
                            <th>Usuario</th>
                            <th>Estado</th>
                        </tr>
                    </thead>
                    <tbody>
    """
    
    for host in other_hosts:
        status_class = f"badge-{host[3].replace('_', '-')}"
        html_content += f"""
                        <tr>
                            <td><strong>#{host[0]}</strong></td>
                            <td>{host[1]}</td>
                            <td>{host[2]}</td>
                            <td><span class="badge {status_class}">{host[3]}</span></td>
                        </tr>
        """
    
    html_content += """
                    </tbody>
                </table>
    """
else:
    html_content += '<p style="color: #999;">Todos los hosts han sido matcheados o no fueron encontrados.</p>'

html_content += """
            </div>
        </div>
        
        <div class="footer">
"""

now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
html_content += f"""
            <p>Reporte generado: {now}</p>
            <p>Base de datos: migration_tracking.db</p>
        </div>
    </div>
</body>
</html>
"""

# Guardar HTML
output_file = '/workspaces/nebula2nebula/migration_report.html'
with open(output_file, 'w', encoding='utf-8') as f:
    f.write(html_content)

conn.close()

print(f"✅ Reporte HTML generado: {output_file}")
print(f"\n📊 Estadísticas:")
print(f"   • Hosts totales: {total_hosts}")
print(f"   • Hosts matched: {matched} ({percentage:.1f}%)")
print(f"   • Hosts pendientes: {pending}")
print(f"   • Endpoints disponibles: {endpoints_count}")
