# Arquitectura, patrones y tecnologías aplicados

## 1. Propósito

Este documento explica cómo se utilizaron los documentos de referencia para diseñar e implementar la API Go.

Documentos utilizados:

1. `analisis-laravel-starter-kit-implementacion_en_go.pdf`.
2. `patron-seguridad-go-backend.pdf`.

Los documentos describen conceptos observados o recomendados a partir de Laravel, Fortify, Sanctum y Spatie Permission. En Go se conservaron los patrones de seguridad y diseño, pero se reemplazaron esos componentes por módulos propios y PostgreSQL.

## 2. Principio de traducción

No se copiaron nombres de clases o paquetes de Laravel. Se tradujeron responsabilidades:

```text
Fortify / Auth       -> auth.Service + SessionStore
Spatie Permission    -> roles + permissions + stores RBAC
Teams / Workspaces   -> organizations + organization_users
Policies             -> resources.Service
Activity Log         -> audit.Service + audit_logs
Sanctum              -> pendiente para el Paso 8
```

El patrón es independiente del paquete que lo implementa. Por ejemplo, Sanctum es una implementación concreta de tokens opacos; el patrón general es una credencial revocable, con hash en base de datos y vencimiento.

## 3. Trazabilidad de patrones

| Patrón | Aplicación en el proyecto | Estado |
|---|---|---|
| Separar identidad y sesión | `users`, `sessions`, `internal/auth` | Implementado |
| Sesión server side | Cookie `sid`, tabla `sessions`, revocación y `session_version` | Implementado |
| Hashing de credenciales | bcrypt para contraseñas y SHA-256 para secretos de sesión | Implementado |
| RBAC por permisos | `RequirePermission`, roles y permisos | Implementado |
| FK reales en RBAC | `user_roles`, `role_permissions`, `user_permissions` | Implementado |
| Permisos directos | Tabla `user_permissions` | Implementado en esquema |
| Tenant / organización | `organizations`, `organization_users`, `organization_id` | Implementado |
| Propiedad de recurso | `documents.owner_id` | Implementado |
| Permisos `.own` y `.any` | `documents.update.own` y `documents.update.any` | Implementado |
| Tenant filtrado en SQL | Consultas con organización y membresía activa | Implementado |
| 404 cross-tenant | Documentos ajenos devuelven `404` | Implementado |
| Policies de recurso | `resources.Service` | Implementado |
| Auditoría append-only | `audit_logs` y trigger de inmutabilidad | Implementado |
| Request ID | Middleware y campo `request_id` | Implementado |
| No registrar secretos | Filtro `safeAuditMetadata` | Implementado |
| Reset hash-only | Previsto en el documento fuente | Pendiente Paso 4 |
| Token opaco Bearer | Previsto en el documento fuente | Pendiente Paso 8 |
| Cuentas técnicas | Previsto en el documento fuente | Pendiente Paso 8 |

## 4. Arquitectura aplicada

### Monolito modular

Se utiliza un único servicio HTTP, organizado por responsabilidades:

```text
cmd/api
internal/config
internal/auth
internal/access
internal/resources
internal/audit
internal/httpapi
internal/store/postgres
internal/migrations
```

Esto mantiene sencilla la ejecución y evita concentrar toda la lógica en un único handler.

### Composición de dependencias

`cmd/api/main.go` conecta el pool de PostgreSQL con los stores y servicios:

```text
PostgreSQL pool
    -> stores PostgreSQL
    -> servicios auth, access, resources y audit
    -> handlers HTTP
    -> servidor net/http
```

Los handlers reciben servicios configurados y no crean conexiones directamente.

### Puertos específicos mediante interfaces

La recomendación de extraer puertos específicos se aplicó mediante:

- `auth.UserStore`.
- `auth.SessionStore`.
- `access.PermissionStore`.
- `resources.OrganizationStore`.
- `resources.DocumentStore`.
- `audit.Store`.

Los servicios dependen de contratos y los adaptadores PostgreSQL implementan esos contratos. Esto permitió probar políticas de documentos con stores falsos sin levantar PostgreSQL.

### Middleware de seguridad

El request pasa por capas:

```text
requestID
    -> securityHeaders
    -> requireSession
    -> requirePermission cuando aplica
    -> policy del recurso
    -> handler
```

Cada capa tiene una responsabilidad específica y responde temprano cuando la solicitud no cumple las condiciones de seguridad.

## 5. Autenticación aplicada

### Registro

```text
JSON de credenciales
    -> normalización de email
    -> validación de contraseña
    -> bcrypt
    -> inserción transaccional del usuario
    -> asignación del rol user
```

La asignación inicial del rol se realiza en la misma transacción que la creación del usuario.

### Login

```text
email + password
    -> buscar usuario
    -> comparar bcrypt
    -> generar secreto aleatorio
    -> guardar hash del secreto
    -> emitir cookie HttpOnly
```

El secreto plano de la sesión no se guarda en PostgreSQL.

### Revocación

La sesión puede invalidarse por logout, `revoked_at`, expiración, cambio de `session_version` o bloqueo del usuario.

## 6. Autorización aplicada

### Permisos en lugar de nombres de rol

Los handlers no dependen de una comparación directa como `user.Role == "admin"`. Las decisiones se basan en permisos efectivos:

```text
users.read
documents.create
documents.update.own
documents.update.any
```

Esto permite cambiar la composición de roles sin modificar todos los endpoints.

### RBAC con FK reales

La relación utilizada es:

```text
users -> user_roles -> roles -> role_permissions -> permissions
users -> user_permissions -> permissions
```

Se evitó una relación polimórfica equivalente a `model_has_roles`, porque las tablas concretas permiten claves foráneas e integridad referencial en PostgreSQL.

### Autorización por recurso

```text
¿Tiene el permiso?
    + ¿Pertenece a la organización?
        + ¿Es propietario o tiene .any?
            -> permitir
```

El documento se consulta junto con la organización y la membresía activa. No se carga primero para filtrarlo posteriormente en memoria.

## 7. Auditoría aplicada

Se tomaron del documento de seguridad estas reglas:

- Registrar operaciones importantes.
- Registrar denegaciones.
- Incluir request ID.
- Incluir actor y recurso.
- No guardar contraseñas ni tokens.
- Evitar actualizar o eliminar eventos históricos.

La implementación registra acción, resultado, ruta, método, código HTTP y metadata segura.

La tabla es append-only mediante un trigger PostgreSQL que rechaza `UPDATE` y `DELETE`.

La recomendación de outbox transaccional, retención y procesamiento asíncrono queda como mejora posterior; el alcance actual usa escritura síncrona best-effort.

## 8. Tecnologías utilizadas

| Tecnología | Uso | Motivo |
|---|---|---|
| Go | Lenguaje principal | Servicios HTTP y binarios autocontenidos. |
| `net/http` | Servidor y routing | Biblioteca estándar suficiente para esta API. |
| PostgreSQL 17 | Persistencia | FK, transacciones, JSONB, índices y triggers. |
| `pgx/v5` | Driver y pool | Acceso directo a PostgreSQL sin ORM obligatorio. |
| `github.com/google/uuid` | Identificadores | IDs no secuenciales para entidades de seguridad y negocio. |
| `golang.org/x/crypto/bcrypt` | Hash de contraseñas | Protección de credenciales humanas. |
| Docker | Empaquetado | Construcción reproducible multi-stage. |
| Docker Compose | Entorno local | API, PostgreSQL y proxy en conjunto. |
| Nginx | Reverse proxy | Punto de entrada único y separación de servicios. |
| `embed.FS` | Migraciones | SQL incluido dentro del binario. |
| JSONB | Metadata de auditoría | Metadata flexible sin guardar secretos. |

## 9. Correspondencia con los documentos fuente

### Análisis del Laravel Starter Kit

Se utilizaron especialmente estas ideas:

- Separar autenticación, sesión, autorización, tenant y auditoría.
- Usar sesiones server side para usuarios humanos.
- Utilizar `session_version` para revocación global.
- No confundir emisión de tokens con una API Bearer consumidora.
- Versionar la API bajo `/api/v1`.
- Usar respuestas JSON y errores de dominio.
- Extraer puertos específicos para casos críticos.
- Traducir responsabilidades en vez de copiar clases de Laravel.

### Patrón de seguridad para Go backend

Se utilizaron especialmente estas ideas:

- Reemplazar tablas polimórficas por relaciones con FK reales.
- Cargar permisos efectivos desde roles y permisos directos.
- Diferenciar permiso general, tenant y recurso.
- Usar `owner_id` para propiedad.
- Definir permisos `.own` y `.any`.
- Validar `organization_id` dentro del SQL.
- Responder `404` cuando el recurso pertenece a otro tenant.
- Crear `audit_logs` separado de `last_used_at`.
- Hacer la auditoría append-only.
- Nunca registrar contraseñas, cookies o tokens.
- Dejar tokens Bearer y cuentas técnicas como una etapa independiente.

## 10. Diferencias entre lo recomendado y lo implementado

| Tema | Recomendación | Estado actual |
|---|---|---|
| Password reset | Hash-only, TTL, consumo único y anti-enumeración | Pendiente por decisión: Paso 4 |
| Sesiones | Server side, expiración y revocación | Implementado |
| RBAC | Roles, permisos directos y FK reales | Implementado |
| Tenant | Organization ID y membresía | Implementado |
| Recurso | Owner, `.own`, `.any` y filtro SQL | Implementado |
| Grants por instancia | Compartir una instancia con otro usuario | Pendiente de una etapa futura |
| Tokens Bearer | Opacos, HMAC, pepper, scopes y revocación | Pendiente por decisión: Paso 8 |
| Cuentas técnicas | Separar ERP/bots de usuarios humanos | Pendiente por decisión: Paso 8 |
| Auditoría | Eventos inmutables sin secretos | Implementado en alcance base |
| Outbox | Desacoplar correo y eventos críticos | Pendiente |
| Cache de permisos | TTL e invalidación | No aplicado; se consulta PostgreSQL directamente |

## 11. Conclusión

La implementación demuestra que los conceptos investigados pueden trasladarse a Go sin copiar la estructura interna de Laravel.

La base actual aplica los patrones más relevantes para usuarios humanos y recursos multi-tenant:

```text
Identidad
    -> sesión server side
    -> permisos efectivos
    -> membresía de organización
    -> policy del recurso
    -> auditoría
```

