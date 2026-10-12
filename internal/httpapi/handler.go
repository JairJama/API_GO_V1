package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"example.com/go-security-api/internal/access"
	"example.com/go-security-api/internal/audit"
	"example.com/go-security-api/internal/auth"
	"example.com/go-security-api/internal/passwordreset"
	"example.com/go-security-api/internal/resources"
	"example.com/go-security-api/internal/serviceaccounts"
	"github.com/jackc/pgx/v5/pgxpool"
)

func NewHandler(database *pgxpool.Pool, authentication *auth.Service, passwordReset *passwordreset.Service, serviceAccounts *serviceaccounts.Service, authorization *access.Service, resourceService *resources.Service, auditor *audit.Service, cookieSecure bool) http.Handler {
	mux := http.NewServeMux()                                                              //Este es el router, asigna rutas a handlers
	mux.HandleFunc("GET /healthz", healthHandler)                                          //rutas basicas para saber si el servidor esta vivo
	mux.HandleFunc("GET /readyz", readyHandler(database))                                  //rutas basicas para saber si el servidor esta listo
	registerAuthRoutes(mux, authentication, passwordReset, auditor, cookieSecure)          //registro de rutas de autenticacion
	registerAccessRoutes(mux, authentication, authorization, auditor)                      //registro de rutas de permisos
	registerResourceRoutes(mux, authentication, serviceAccounts, resourceService, auditor) //registro de rutas de recursos
	registerServiceAccountRoutes(mux, authentication, serviceAccounts, authorization, auditor)

	return securityHeaders(requestID(mux))
}

func readyHandler(database *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if database == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status":     "not_ready",
				"dependency": "database_not_configured",
				"request_id": requestIDFromContextValue(r.Context()),
			})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := database.Ping(ctx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status":     "not_ready",
				"dependency": "database",
				"request_id": requestIDFromContextValue(r.Context()),
			})
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"status":     "ready",
			"dependency": "database",
			"request_id": requestIDFromContextValue(r.Context()),
		})
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":     "ok",
		"service":    "go-security-api",
		"request_id": requestIDFromContextValue(r.Context()),
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
	})
}

type contextKey string

const requestIDKey contextKey = "request_id"

func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID") //obtiene el id de la peticion
		if id == "" {
			id = newRequestID() //genera un nuevo id si no existe
		}

		w.Header().Set("X-Request-ID", id)           //establece el id de la peticion
		ctx := withRequestIDContext(r.Context(), id) //crea un nuevo contexto con el id de la peticion
		next.ServeHTTP(w, r.WithContext(ctx))        //llama al siguiente handler con el nuevo contexto
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff") // No permite que el navegador adivine el tipo de archivo
		w.Header().Set("X-Frame-Options", "DENY")           // No permite que la pagina se cargue dentro de un iframe
		w.Header().Set("Referrer-Policy", "no-referrer")    // No envia el url de origen al hacer requests
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func newRequestID() string {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "request-id-unavailable"
	}
	return hex.EncodeToString(bytes[:])
}
