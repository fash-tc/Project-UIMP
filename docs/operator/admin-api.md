# admin-api Operator Guide (Slice 1)

## Running locally
- Port 8096 (proxied through nginx at `/api/admin/*`)
- DB: `/data/admin.db` inside the container, `admin_data` volume on host.

## Bypass token (emergency RBAC override)
Set `ADMIN_BYPASS_TOKEN=<random-string>` in `~/uip/.env`, restart admin-api, then:
```
curl -H "X-Admin-Bypass: <token>" http://10.177.154.196/api/admin/config
```
Every bypass request emits `audit_bypass=true` log line. Unset the token after use.

## Resetting seeds
Bumping `config_seed.json` version + restarting admin-api auto-applies new keys.
The existing values are preserved.

## Reading the audit log
```
curl -H "Cookie: session=<your-cookie>" http://10.177.154.196/api/admin/audit?key=ai.enricher.model | jq
```

## Regenerating uip_config_client/schemas.py
After editing `admin-api/seeds/config_seed.json`:
```
python deploy/admin-api/build_schemas.py
```
Commit the generated file.
