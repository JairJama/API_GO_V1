# Paso 8: cuentas técnicas y tokens Bearer

## Objetivo

Permitir integraciones no humanas sin reutilizar cuentas de usuarios, mediante cuentas técnicas asociadas a una organización y tokens Bearer opacos, revocables y de duración limitada.

## Implementación

- La migración `006_service_accounts_tokens.sql` crea `service_accounts`, sus relaciones de roles y permisos, y `api_tokens`.
- Se agregaron los permisos `service_accounts.manage`, `api_tokens.issue` y `api_tokens.revoke`, además del rol `erp-reader` con `documents.read`.
- Cada token usa el formato `atk_<uuid>_<base64url-secret>`. El secreto tiene 32 bytes aleatorios y solo se devuelve durante la emisión.
- PostgreSQL conserva exclusivamente HMAC-SHA256 del token. La clave está fuera de la base de datos en `API_TOKEN_PEPPER`.
- La expiración es obligatoria y no puede superar treinta días. El scope `*` no se admite; cada scope debe ser un permiso efectivo de la cuenta técnica.
- `AuthenticatePrincipal` prioriza `Authorization: Bearer` sobre la cookie. Un Bearer presente e inválido responde `401`, sin usar la sesión como fallback.
- Un principal técnico solo puede leer documentos de la organización de su cuenta con permiso y scope `documents.read`. Las mutaciones continúan exigiendo principal humano.
- Se actualizan `last_used_at` y `last_used_ip` en cada autenticación Bearer válida. La revocación conserva la fila y establece `revoked_at`.
- Auditoría registra la creación de cuentas, emisión/revocación de tokens y autenticación Bearer. Nunca incluye token, secreto, pepper, cookie ni cabecera `Authorization`.

## Endpoints

| Método | Ruta | Permiso humano |
|---|---|---|
| POST | `/api/v1/organizations/{organization_id}/service-accounts` | `service_accounts.manage` |
| GET | `/api/v1/organizations/{organization_id}/service-accounts` | `service_accounts.manage` |
| POST | `/api/v1/service-accounts/{service_account_id}/tokens` | `api_tokens.issue` |
| GET | `/api/v1/service-accounts/{service_account_id}/tokens` | `api_tokens.issue` |
| DELETE | `/api/v1/service-accounts/{service_account_id}/tokens/{token_id}` | `api_tokens.revoke` |

Ejemplo de cuenta técnica:

```json
{"name":"ERP de la organización","slug":"erp-reader","roles":["erp-reader"]}
```

Ejemplo de token:

```json
{"name":"Integración ERP producción","scopes":["documents.read"],"expires_at":"2026-12-31T23:59:59Z"}
```

La creación devuelve `token` y `metadata`; las consultas posteriores solo devuelven metadata.

## Validación

- `go test ./...` cubre la emisión, hash HMAC, scopes, revocación y formato de token.
- `go vet ./...` valida los paquetes.
- El flujo completo se puede validar detrás de Nginx con una cuenta humana administradora, una cuenta `erp-reader` y una solicitud Bearer al endpoint de lectura.

## Operación

`API_TOKEN_PEPPER` es obligatorio. Debe configurarse como secreto diferente por entorno, fuera del repositorio. Al rotarlo, los tokens existentes dejarán de autenticar y deberán emitirse de nuevo.
