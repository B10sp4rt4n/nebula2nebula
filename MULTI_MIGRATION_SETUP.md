# Multi-Migration Setup Guide

## 📋 Overview

La app ahora soporta **múltiples migraciones simultáneas** sin modificar código.  
Cada migración tiene su propia configuración SOURCE y TARGET en el `.env`.

---

## 🔧 Estructura Actual

### Migración 1: EDRON Legacy → EDRON Academy
- **SOURCE:** Consola legacy Edron  
- **TARGET:** Consola Edron Academy (destino)

### Migración 2: MLTi TeamViewer → MLTi Nebula  
- **SOURCE:** TeamViewer console (legacy)  
- **TARGET:** MLTi Nebula (destino recién creada)

---

## ➕ Cómo Agregar una Nueva Migración

### Paso 1: Obtén las credenciales
Reúne de ambas consolas:
- `CLIENT_ID`
- `CLIENT_SECRET`  
- `ACCOUNT_ID`

### Paso 2: Agrega las variables al `.env`

Busca el número más alto actual en `.env` (ej: `MIGRATION_2_*`), y crea una nueva sección:

```dotenv
# --------------------
# MIGRATION 3: [Source Name] → [Target Name]
# --------------------
MIGRATION_3_NAME=[Descripción clara de la migración]
MIGRATION_3_SOURCE_API_BASE_URL=https://api.malwarebytes.com
MIGRATION_3_SOURCE_TOKEN_URL=https://api.malwarebytes.com/oauth2/token
MIGRATION_3_SOURCE_CLIENT_ID=tu_source_client_id
MIGRATION_3_SOURCE_CLIENT_SECRET=tu_source_client_secret
MIGRATION_3_SOURCE_ACCOUNT_ID=tu_source_account_id
MIGRATION_3_SOURCE_SCOPE=read write execute
MIGRATION_3_SOURCE_ENDPOINTS_PATH=/nebula/v1/endpoints

MIGRATION_3_TARGET_API_BASE_URL=https://api.malwarebytes.com
MIGRATION_3_TARGET_TOKEN_URL=https://api.malwarebytes.com/oauth2/token
MIGRATION_3_TARGET_CLIENT_ID=tu_target_client_id
MIGRATION_3_TARGET_CLIENT_SECRET=tu_target_client_secret
MIGRATION_3_TARGET_ACCOUNT_ID=tu_target_account_id
MIGRATION_3_TARGET_SCOPE=read write execute
MIGRATION_3_TARGET_MOVE_ENDPOINT_PATH=/nebula/v1/jobs
```

### Paso 3: Selecciona en la UI

Al ejecutar la app, verás un selector dropdown que automáticamente detecta todas las migraciones configuradas.

---

## 🎯 Cambios en la App

### Antes (una sola migración)
```
SOURCE_CLIENT_ID=...
TARGET_CLIENT_ID=...
```

### Ahora (múltiples migraciones)
```
MIGRATION_1_SOURCE_CLIENT_ID=...
MIGRATION_1_TARGET_CLIENT_ID=...
MIGRATION_2_SOURCE_CLIENT_ID=...
MIGRATION_2_TARGET_CLIENT_ID=...
```

---

## 🚀 Cómo Ejecutar

```bash
python3 -m streamlit run threatdown_token_streamlit_app.py
```

1. Abre `http://localhost:8501`
2. Verás un dropdown con las migraciones disponibles
3. Selecciona la que quieras ejecutar
4. El resto de la interfaz usa la configuración de esa migración

---

## 🔄 Variables Globales vs. Por Migración

| Tipo | Ubicación | Ejemplo |
|------|-----------|---------|
| **Global** | Aplican a todas | `PAGE_SIZE=200`, `DRY_RUN=true` |
| **Por Migración** | Específicas de cada una | `MIGRATION_1_SOURCE_CLIENT_ID=...` |

---

## ✅ Validación

Para verificar que todo está configurado correctamente:

```bash
cd /workspaces/nebula2nebula

# Verificar sintaxis Python
python3 -m py_compile threatdown_token_streamlit_app.py

# Cargar el .env (si usas bash)
set -a && source .env && set +a
env | grep MIGRATION_
```

---

## 📌 Notas Importantes

1. **Credenciales en `.env`**: ⚠️ Rotar regularmente y considerar usar un vault.
2. **DRY_RUN=true**: Por defecto, simula la migración sin mover endpoints.
3. **Backward Compatible**: Si solo tienes `MIGRATION_1_*`, no hay selector (interfaz limpia).
4. **Escalable**: Agregá migraciones sin limitar a 2. El sistema detecta todas automáticamente.

---

## 🆘 Troubleshooting

### "No se detectaron consolas configuradas"
→ Verifica que las credenciales estén completas en el `.env`.

### El selector no aparece
→ Solo se muestra si hay 2+ migraciones. Con 1 sola, la app usa esa directamente.

### Errores de token
→ Valida que `CLIENT_SECRET` y `ACCOUNT_ID` sean correctos (copiar/pegar exacto del email).

---

## 📞 Referencia Rápida

```dotenv
# Agregar una migración N es copiar/pegar:
MIGRATION_N_NAME=...
MIGRATION_N_SOURCE_*=...
MIGRATION_N_TARGET_*=...
```

Todo lo demás es automático. ✅
