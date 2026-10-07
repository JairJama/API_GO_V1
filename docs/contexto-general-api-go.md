# Contexto general de la API Go

## 1. Propósito

Este proyecto implementa una API backend en Go para demostrar autenticación, sesiones, autorización, aislamiento por organización, autorización sobre recursos y auditoría.

La solución toma como referencia el análisis técnico del Laravel Starter Kit y el patrón de seguridad para un backend en Go. Los documentos se utilizaron para identificar responsabilidades, riesgos y patrones; no se copiaron literalmente las clases o paquetes de Laravel.

El objetivo es contar con una base funcional, dockerizada y comprobable que muestre cómo trasladar estos conceptos a una API Go utilizando PostgreSQL y Nginx.

## 2. Arquitectura general

```text
Cliente HTTP
    |
    v
Nginx reverse proxy :8080
    |
    v
API Go con net/http :8080
    |
    +--> autenticación y sesiones
    +--> autorización RBAC
    +--> organizaciones y documentos
    +--> auditoría
    |
    v
PostgreSQL 17
```

La composición de dependencias se realiza en `cmd/api/main.go`. Los handlers HTTP reciben servicios ya configurados y no construyen conexiones directamente.

##  3. Componentes principales

### API HTTP

Se utiliza `net/http` de la biblioteca estándar. No se incorporó un framework HTTP porque el proyecto busca demostrar una organización idiomática de Go con herramientas nativas y contratos explícitos.

Responsabilidades:

- Registrar rutas.
- Validar solicitudes JSON.
- Aplicar middleware de request ID, seguridad, sesión y permisos.
- Traducir errores de dominio a respuestas HTTP.
- Devolver respuestas JSON.

### PostgreSQL

PostgreSQL conserva la información persistente y las relaciones de seguridad mediante claves foráneas reales.

Migraciones actuales:

```text
001_initial.sql
002_sessions.sql
003_rbac.sql
004_audit_logs.sql
```

Las migraciones se embeben con `embed.FS` y se controlan mediante `schema_migrations`.

### Docker Compose y Nginx

Docker Compose levanta:

- `api`: aplicación Go compilada con Dockerfile multi-stage.
- `postgres`: PostgreSQL 17.
- `nginx`: reverse proxy Nginx 1.27.

El flujo externo es:

```text
Cliente -> Nginx -> API Go
```

## 4. Modelo de seguridad

### Identidad y sesiones

Los usuarios se almacenan en `users`. Las contraseñas se protegen con bcrypt.

El login crea una sesión en PostgreSQL y entrega una cookie HttpOnly llamada `sid`. En la base de datos se almacena únicamente el hash SHA-256 del secreto de sesión.

La sesión se valida mediante existencia, comparación en tiempo constante, expiración, revocación individual y `session_version`.

### Roles y permisos

La autorización utiliza permisos y no comparaciones directas con nombres de roles dentro de los handlers.

Tablas principales:

```text
roles
permissions
role_permissions
user_roles
user_permissions
```

Permisos implementados:

```text
users.read
users.manage
documents.read
documents.create
documents.update.own
documents.update.any
documents.delete.own
documents.delete.any
```

### Autorización por recurso

La autorización de documentos combina:

1. El permiso general.
2. La membresía activa en la organización.
3. La propiedad del documento o el permiso `.any`.

El filtro de organización se realiza directamente en SQL. Si el documento pertenece a otra organización o el usuario no tiene membresía, se responde `404` para no revelar su existencia.

### Auditoría

`audit_logs` registra `request_id`, actor, acción, resultado, método, ruta, código HTTP, recurso y metadata JSON segura.

Un trigger PostgreSQL evita actualizar o eliminar registros, haciendo que la tabla sea append-only. No se almacenan contraseñas, cookies, tokens ni secretos.

## 5. Endpoints actuales

### Salud

```text
GET /healthz
GET /readyz
```

### Autenticación y sesiones

```text
POST /api/v1/auth/register
POST /api/v1/auth/login
POST /api/v1/auth/logout
GET  /api/v1/auth/me
```

### Autorización

```text
GET /api/v1/admin/access
```

### Organizaciones y documentos

```text
POST   /api/v1/organizations
POST   /api/v1/organizations/{organization_id}/documents
GET    /api/v1/organizations/{organization_id}/documents/{document_id}
PATCH  /api/v1/organizations/{organization_id}/documents/{document_id}
DELETE /api/v1/organizations/{organization_id}/documents/{document_id}
```

## 6. Validación realizada

Se validó:

- `go test ./...`.
- `go vet ./...`.
- `docker compose config --quiet`.
- Construcción Docker sin caché.
- Pruebas pasando por Nginx.
- Autenticación y logout.
- RBAC con `403` y `200`.
- Aislamiento entre organizaciones con `404`.
- Permisos `.own` y `.any`.
- Auditoría y trigger append-only.
- Migraciones idempotentes después de reiniciar la API.

## 7. Pendientes y límites

No forman parte del alcance actual:

- Recuperación de contraseña.
- Tokens Bearer, scopes y cuentas técnicas.
- 2FA y OAuth.
- SMTP real, Redis y workers de correo.
- Outbox transaccional completo.
- Kubernetes.

Estos elementos pueden implementarse como nuevas etapas sin cambiar la base modular existente.

## 8. Ubicación

```text
C:\Users\kdtja\Desktop\API_GO
```

La documentación general se mantiene directamente en `docs/`. La carpeta `docs/steps/` contiene documentación operativa por etapa y está excluida del control de versiones mediante `.gitignore`.
