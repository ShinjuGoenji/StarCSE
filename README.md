# Oasis Star CSE

## Build

```
pip install -r requirements.txt && chmod +x ./cosmian
```

## Deploy

```
uvicorn main:app --host 0.0.0.0
```

## Caution

- Backend Url my need to be modified in [script.js](./static/script.js).

```javascript
const backendUrl = "http://0.0.0.0:8000";
```

- Datavbase Url my need to be modified in [.env](./.env) if you want to use your own db.

```
postgresql+asyncpg://oasis_star_cse_db_user:LaVHxRy3eQl8uU7TEEf3EPNf3tycmKcl@dpg-d0ll20hr0fns738frk90-a.oregon-postgres.render.com:5432/oasis_star_cse_db
```

- Certificate Url may need to be modified in [certificate.py](./certificate.py) for your own PKI

```python
api_url = "https://certificate-ed4n.onrender.com/api/issue"
```

- KMS Url may need to be modified in [kms.py](./kms.py) for your own cosmian kms server

```python
CMD = [
    "./cosmian",
    "--kms-url",
    "https://4d7f-140-113-229-196.ngrok-free.app",
    "--kms-accept-invalid-certs",
    "kms",
]
```
