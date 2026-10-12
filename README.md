# Go Security API

API base en Go para demostrar autenticacion, sesiones, autorizacion, aislamiento por organizacion, tokens y auditoria.

## Estado actual


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
- Recuperación de contraseña con token opaco de un solo uso, almacenado solo como hash SHA-256.
- Expiración de token configurable (una hora por defecto), invalidación de tokens anteriores y revocación de todas las sesiones al completar el cambio.
- Mailer de desarrollo que escribe el enlace solo cuando `APP_ENV=development`; en otros entornos queda deshabilitado hasta configurar un proveedor SMTP.
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


## Ejecutar

Requisitos: Go 1.25 o compatible y Docker Desktop con Docker Compose.

Levantar el entorno: `docker compose up --build`.

Probar mediante Nginx: `Invoke-RestMethod http://localhost:8080/healthz`.

Comprobar disponibilidad de PostgreSQL mediante Nginx: `Invoke-RestMethod http://localhost:8080/readyz`.

Registrar un usuario: `POST /api/v1/auth/register`.

Iniciar sesión: `POST /api/v1/auth/login`.

Solicitar recuperación de contraseña: `POST /api/v1/auth/password/forgot` con `{"email":"usuario@example.com"}`. La respuesta siempre es `202 Accepted` cuando el mailer está disponible. En desarrollo, revisar los logs del contenedor API para obtener el enlace de prueba; no usar este mecanismo en producción.

Cambiar contraseña: `POST /api/v1/auth/password/reset` con `{"token":"...","password":"nueva-clave-segura"}`. Una solicitud correcta devuelve `204 No Content`.

Consultar la sesión: `GET /api/v1/auth/me`.

Consultar la autorización efectiva de un usuario administrador: `GET /api/v1/admin/access`.

Crear una organización: `POST /api/v1/organizations`.

Crear un documento: `POST /api/v1/organizations/{organization_id}/documents`.

Consultar, actualizar o eliminar un documento: `GET`, `PATCH` o `DELETE` en `/api/v1/organizations/{organization_id}/documents/{document_id}`.

Los eventos de auditoría se almacenan en PostgreSQL en la tabla `audit_logs` y no tienen endpoint público en esta etapa.

Variables de recuperación: `APP_ENV`, `PASSWORD_RESET_TTL` y `PASSWORD_RESET_URL_BASE`. Para producción, establecer `APP_ENV` distinto de `development` y sustituir el mailer de logs por una implementación SMTP antes de habilitar la recuperación.

Ejecutar pruebas locales: `go test ./...`.

Detener el entorno: `docker compose down`.
