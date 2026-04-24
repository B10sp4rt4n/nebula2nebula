#!/usr/bin/env python3
"""
Script para exportar endpoints disponibles desde el origen
"""
import sys
sys.path.insert(0, '/workspaces/nebula2nebula')

import os
import json
from dotenv import load_dotenv
from threatdown_token_streamlit_app import get_token, get_all_endpoints
import warnings
warnings.filterwarnings('ignore')

load_dotenv()

print("=" * 80)
print("📡 EXPORTAR ENDPOINTS DISPONIBLES")
print("=" * 80)

print("\n🔐 Obteniendo token del origen...")
try:
    token = get_token(
        os.getenv('SOURCE_TOKEN_URL'),
        os.getenv('SOURCE_CLIENT_ID'),
        os.getenv('SOURCE_CLIENT_SECRET'),
        os.getenv('SOURCE_SCOPE')
    )
    print(f"✅ Token obtenido")
    
    print("\n📡 Obteniendo endpoints...")
    all_endpoints, stats = get_all_endpoints(
        token,
        os.getenv('SOURCE_ENDPOINTS_PATH'),
        os.getenv('SOURCE_API_BASE_URL'),
        "POST",
        os.getenv('SOURCE_ACCOUNT_ID'),
        int(os.getenv('PAGE_SIZE', 200)),
        int(os.getenv('MAX_PAGES', 0))
    )
    
    if all_endpoints:
        print(f"✅ Endpoints obtenidos: {len(all_endpoints)}")
        
        # Guardar endpoints en JSON
        output_file = '/workspaces/nebula2nebula/endpoints_origin.json'
        with open(output_file, 'w') as f:
            json.dump(all_endpoints, f, indent=2)
        
        print(f"\n✅ Endpoints guardados en: {output_file}")
        print(f"\n📊 Estadísticas:")
        print(f"   - Total: {len(all_endpoints)}")
        print(f"   - Con machine_id: {sum(1 for ep in all_endpoints if ep.get('machine_id'))}")
        print(f"   - Con nombre: {sum(1 for ep in all_endpoints if ep.get('name'))}")
        
        # Mostrar primeros 5
        print(f"\n📋 Primeros 5 endpoints:")
        for i, ep in enumerate(all_endpoints[:5], 1):
            print(f"   {i}. {ep.get('name', 'N/A')} (ID: {ep.get('machine_id', 'N/A')[:8]}...)")
            
    else:
        print(f"❌ Error: {stats}")
        
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
