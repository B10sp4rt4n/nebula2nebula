# nebula2nebula
migración de nebula a nebula

## Ejecutar la app web (Streamlit)

1. Instala dependencias:

```bash
python3 -m pip install -r requirements.txt
```

2. Configura tus variables en `.env` (ya incluye plantillas SOURCE/TARGET).

3. Inicia la app:

```bash
python3 -m streamlit run threatdown_token_streamlit_app.py
```

4. Abre en el navegador:

- `http://localhost:8501`

## Listar endpoints desde consola

Usando variables de entorno:

```bash
export THREATDOWN_CLIENT_ID="tu_client_id"
export THREATDOWN_CLIENT_SECRET="tu_client_secret"
python list_endpoints_cli.py
```

Salida en JSON:

```bash
python list_endpoints_cli.py --output json
```

Salida en CSV por pantalla:

```bash
python list_endpoints_cli.py --output csv
```

Guardar CSV en archivo:

```bash
python list_endpoints_cli.py --output csv --csv-file endpoints.csv
```

Usando token ya generado:

```bash
python list_endpoints_cli.py --token "tu_access_token"
```

Si recibes 404 en la ruta de listado, prueba indicando la ruta explícitamente:

```bash
python list_endpoints_cli.py --token "tu_access_token" --endpoints-path "/nebula/v1/endpoints"
```

También puedes dejarla fija por variable de entorno:

```bash
export THREATDOWN_ENDPOINTS_PATH="/nebula/v1/endpoints"
```
