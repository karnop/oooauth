package v1

import (
	"encoding/json"
	"net/http"

	"auth/internal/auth"
	"auth/internal/http/middleware"
	"auth/internal/http/response"
)

type UserHandler struct {
	authService *auth.Service
}

func NewUserHandler(authService *auth.Service) *UserHandler {
	return &UserHandler{authService: authService}
}

type UpdateProfileRequest struct {
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	AvatarURL string `json:"avatar_url"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// GetMe handles GET /v1/users/me
func (h *UserHandler) GetMe(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok {
		response.Problem(w, r, http.StatusUnauthorized, "Unauthorized", "User context not found", "UNAUTHORIZED")
		return
	}

	response.JSON(w, http.StatusOK, map[string]any{
		"user": user,
	})
}

// UpdateMe handles PATCH /v1/users/me
func (h *UserHandler) UpdateMe(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok {
		response.Problem(w, r, http.StatusUnauthorized, "Unauthorized", "User context not found", "UNAUTHORIZED")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req UpdateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Problem(w, r, http.StatusBadRequest, "Invalid Request Body", "Request payload must be valid JSON", "INVALID_JSON")
		return
	}

	updatedUser, err := h.authService.UpdateProfile(r.Context(), user.ID, req.FirstName, req.LastName, req.AvatarURL)
	if err != nil {
		response.Error(w, r, err)
		return
	}

	response.JSON(w, http.StatusOK, map[string]any{
		"user": updatedUser,
	})
}

// ChangePassword handles POST /v1/users/me/change-password
func (h *UserHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	user, ok := middleware.UserFromContext(r.Context())
	if !ok {
		response.Problem(w, r, http.StatusUnauthorized, "Unauthorized", "User context not found", "UNAUTHORIZED")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response.Problem(w, r, http.StatusBadRequest, "Invalid Request Body", "Request payload must be valid JSON", "INVALID_JSON")
		return
	}

	if err := h.authService.ChangePassword(r.Context(), user.ID, req.CurrentPassword, req.NewPassword); err != nil {
		response.Error(w, r, err)
		return
	}

	response.JSON(w, http.StatusOK, map[string]string{
		"message": "password changed successfully; all other active sessions have been revoked",
	})
}
