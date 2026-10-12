# Paso 4: recuperación de contraseña

## Objetivo

Permitir que un usuario humano restablezca su contraseña sin exponer si una dirección de correo está registrada, sin guardar secretos planos y revocando las sesiones existentes después del cambio.

## Qué se implementó

- Migración `005_password_reset_tokens.sql` con tokens de recuperación hash-only, fecha de expiración, consumo único, índice por usuario, índice por expiración y restricción de un token activo por usuario.
- Módulo `internal/passwordreset` separado de `internal/auth`.
- Generación de 32 bytes aleatorios para cada token; el enlace usa un token opaco con prefijo `prt_` y se almacena únicamente su hash SHA-256.
- Invalidación de todos los tokens de recuperación anteriores al solicitar uno nuevo.
- Restablecimiento atómico: consume el token, actualiza el hash bcrypt de la contraseña, incrementa `session_version` y revoca todas las sesiones del usuario en una única transacción de PostgreSQL.
- Endpoints `POST /api/v1/auth/password/forgot` y `POST /api/v1/auth/password/reset`.
- Respuesta uniforme `202 Accepted` para solicitudes válidas de recuperación, exista o no el correo. Un token inválido, expirado, consumido o una contraseña fuera de la política devuelve `400` durante el restablecimiento.
- Limitador local en memoria: tres solicitudes por correo y quince minutos; cinco por IP y quince minutos. Cuando se supera el límite, se conserva el `202` para no revelar información.
- `LogMailer` para desarrollo. Solo se activa si `APP_ENV=development` y escribe el enlace de prueba en el log de la API. Fuera de desarrollo, el mailer queda deshabilitado y el endpoint devuelve `503` hasta integrar SMTP.
- Auditoría de `auth.password_reset.requested`, `auth.password_reset.completed` y `auth.password_reset.denied`, sin token, contraseña, cookie, hash ni enlace.

## Por qué se implementó

El flujo de recuperación suele ser un punto sensible: un token reutilizable, almacenado en texto plano o una respuesta que diferencia correos existentes facilita el acceso no autorizado. La implementación conserva el patrón de sesiones server-side para personas y usa tokens de recuperación únicamente como credenciales temporales de un solo uso.

## Para qué sirve

Un usuario que olvidó su contraseña puede obtener un enlace temporal, definir una clave nueva y cerrar automáticamente cualquier sesión anterior que pudiera estar comprometida. La separación por interfaces permite sustituir el mailer de desarrollo por SMTP sin cambiar el flujo principal.

## Herramientas utilizadas

- Go estándar: `crypto/rand`, `crypto/sha256`, `net/http`, `log/slog`, `net/url`, `sync` y `context`.
- `golang.org/x/crypto/bcrypt` para el hash de la contraseña.
- PostgreSQL y `pgx/v5` para transacciones y persistencia.
- Docker Compose y Nginx existentes para comprobar el flujo mediante el proxy.
- Pruebas unitarias con `go test`.

## Archivos modificados

- `internal/migrations/sql/005_password_reset_tokens.sql`: esquema de tokens.
- `internal/passwordreset/passwordreset.go`: servicio, interfaces y lógica de token.
- `internal/passwordreset/ratelimiter.go`: limitador local.
- `internal/passwordreset/mailer.go`: mailer de desarrollo y mailer no disponible.
- `internal/store/postgres/password_reset.go`: persistencia y transacción atómica.
- `internal/httpapi/password_reset_handlers.go`: endpoints HTTP.
- `internal/auth/service.go`: política de email y contraseña exportada para reutilizarla.
- `internal/config/config.go`, `cmd/api/main.go`, `docker-compose.yml` y `.env.example`: configuración y conexión de dependencias.
- `README.md`: uso y variables del flujo.
- Pruebas en `internal/passwordreset`, `internal/config`, `internal/httpapi` e `internal/migrations`.

## Cómo ejecutarlo

1. Levantar el entorno:

   ```powershell
   docker compose up --build
   ```

2. Registrar un usuario o usar uno existente.

3. Solicitar la recuperación a través de Nginx:

   ```powershell
   Invoke-WebRequest -Method POST http://localhost:8080/api/v1/auth/password/forgot -ContentType 'application/json' -Body '{"email":"usuario@example.com"}'
   ```

4. En desarrollo, consultar el log para obtener el enlace temporal:

   ```powershell
   docker compose logs api
   ```

5. Extraer el valor del parámetro `token` y enviarlo con la contraseña nueva:

   ```powershell
   Invoke-WebRequest -Method POST http://localhost:8080/api/v1/auth/password/reset -ContentType 'application/json' -Body '{"token":"prt_...","password":"nueva-clave-segura"}'
   ```

La contraseña debe tener entre 8 y 72 caracteres. El endpoint de solicitud retorna `202` también si el correo no existe o se aplicó el límite. No poner el enlace ni el token en capturas, commits o tickets.

## Pruebas realizadas

- `go test ./...` valida todos los paquetes.
- Las pruebas de `internal/passwordreset` validan que el token almacenado es el hash SHA-256, no coincide con el token entregado, solo funciona una vez, expira y un token nuevo invalida al anterior.
- La prueba HTTP valida que las solicitudes para un correo existente e inexistente reciben el mismo `202`, y que el endpoint de cambio consume el token una sola vez.
- Las pruebas validan que un restablecimiento aumenta `session_version` y genera un hash bcrypt para la nueva contraseña.
- Las pruebas del limitador cubren el máximo de tres solicitudes por correo.
- Las pruebas de auditoría existentes comprueban que claves sensibles, incluidos tokens y contraseñas, se eliminan de metadata.

## Limitaciones actuales

- El mailer solo es adecuado para desarrollo; no envía correo real. En producción el flujo queda intencionalmente no disponible hasta incorporar SMTP o un proveedor transaccional.
- El limitador está en memoria de cada instancia. Al usar más de una réplica o reiniciar la API, el conteo no se comparte ni persiste; Redis u otro almacenamiento compartido resolvería esa limitación.
- No se agregaron 2FA, notificaciones de cambio de contraseña ni colas de correo, porque están fuera del alcance inicial.

## Resultado

La API tiene un flujo de recuperación de contraseña con protección contra enumeración básica, tasa limitada, token temporal no reutilizable y revocación de sesiones. Se conserva la arquitectura Go con `net/http`, PostgreSQL, `pgx/v5`, Docker y Nginx.
