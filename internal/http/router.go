package http

import (
	"auth/internal/auth"
	"auth/internal/config"
	"auth/internal/database"
	"auth/internal/http/middleware"
	v1 "auth/internal/http/v1"
	"net/http"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

func NewRouter(cfg *config.Config, db *database.DB, authService *auth.Service) http.Handler {
	r := chi.NewRouter()

	// global prod middlewares
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.Logger)
	r.Use(chimiddleware.Recoverer)

	// cors
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   cfg.AllowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// health check endpoints for load balancers, probes
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	// initialize handlers and middlewares
	authMiddleware := middleware.NewAuthMiddleware(authService, cfg.CookieSecure)
	authHandler := v1.NewAuthHandler(authService, cfg)
	userHandler := v1.NewUserHandler(authService)

	// API v1 routes
	r.Route("/v1", func(r chi.Router) {
		r.Route("/auth", func(r chi.Router) {
			// public auth routes
			// password auth
			r.Post("/sign-up", authHandler.SignUp)
			r.Post("/sign-in", authHandler.SignIn)
			r.Post("/sign-out", authHandler.SignOut)

			// passwordless auth
			r.Post("/magic-link/send", authHandler.SendMagicLink)
			r.Post("/magic-link/verify", authHandler.VerifyMagicLink)
			r.Get("/magic-link/verify", authHandler.VerifyMagicLink)

			r.Post("/otp/send", authHandler.SendOTP)
			r.Post("/otp/verify", authHandler.VerifyOTP)

			r.Post("/verify-email", authHandler.VerifyEmail)
			r.Get("/verify-email", authHandler.VerifyEmail) // Link click support

			//  protected auth routes
			r.Group(func(r chi.Router) {
				r.Use(authMiddleware.RequireAuth)
				r.Post("/sign-out-all", authHandler.SignOutAll)
			})
		})

		// protected user routes
		r.Route("/users", func(r chi.Router) {
			r.Use(authMiddleware.RequireAuth)
			r.Get("/me", userHandler.GetMe)
			r.Patch("/me", userHandler.UpdateMe)
			r.Post("/me/change-password", userHandler.ChangePassword)
		})

	})

	return r
}
