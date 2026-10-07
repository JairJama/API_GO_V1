# Go Security API

API base en Go para demostrar autenticacion, sesiones, autorizacion, aislamiento por organizacion, tokens y auditoria.

## Estado actual

Implementados y validados los Pasos 1, 2, 3, 5, 6, 7 y 9:

- Servidor HTTP con `net/http`.
- Endpoint `GET /healthz`.
- Request ID y cabeceras de seguridad basicas.
- Dockerfile multi-stage.
- Docker Compose con API, PostgreSQL preparado y Nginx.
- Nginx como reverse proxy hacia la API.
- Configuracion de PostgreSQL mediante variables de entorno.
- Pool de conexiones con `pgx/v5`.
- Migracion inicial embebida en el binario.
- Tablas `users`, `organizations`, `organization_users` y `documents`.
- Endpoint `GET /readyz` para comprobar la base de datos.
- Registro, login, logout y `GET /api/v1/auth/me`.
- Sesiones server side con cookie HttpOnly.
- Revocación por sesión y por `session_version`.
- Roles, permisos y asignaciones explícitas mediante RBAC.
- Middleware de autorización basado en permisos efectivos.
- Endpoint de demostración `GET /api/v1/admin/access`.
- Creación de organizaciones con asociación automática del propietario.
- Creación, consulta, actualización y eliminación de documentos.
- Aislamiento por organización mediante membresía activa.
- Policies para distinguir permisos `.own` y `.any`.
- Auditoría append-only de autenticación, autorización y documentos.
- Registro de `request_id`, actor, acción, resultado, ruta, método y código HTTP.
- Validación final de Docker, Nginx, PostgreSQL, autenticación, autorización, aislamiento y auditoría.

El Paso 4, recuperación de contraseña, fue dejado pendiente intencionalmente para esta iteración. La autorización por organización y recurso ya está implementada en el Paso 6.
El Paso 8, tokens Bearer y cuentas técnicas, también fue dejado pendiente por decisión de alcance.

## Ejecutar

Requisitos: Go 1.25 o compatible y Docker Desktop con Docker Compose.

Levantar el entorno: `docker compose up --build`.

Probar mediante Nginx: `Invoke-RestMethod http://localhost:8080/healthz`.

Comprobar disponibilidad de PostgreSQL mediante Nginx: `Invoke-RestMethod http://localhost:8080/readyz`.

Registrar un usuario: `POST /api/v1/auth/register`.

Iniciar sesión: `POST /api/v1/auth/login`.

Consultar la sesión: `GET /api/v1/auth/me`.

Consultar la autorización efectiva de un usuario administrador: `GET /api/v1/admin/access`.

Crear una organización: `POST /api/v1/organizations`.

Crear un documento: `POST /api/v1/organizations/{organization_id}/documents`.

Consultar, actualizar o eliminar un documento: `GET`, `PATCH` o `DELETE` en `/api/v1/organizations/{organization_id}/documents/{document_id}`.

Los eventos de auditoría se almacenan en PostgreSQL en la tabla `audit_logs` y no tienen endpoint público en esta etapa.

Ejecutar pruebas locales: `go test ./...`.

Detener el entorno: `docker compose down`.
