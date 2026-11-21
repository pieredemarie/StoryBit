package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"storybit/auth-service/services"
)

type Handler struct{ auth *services.AuthService }

func New(logger *slog.Logger, svc *services.AuthService) http.Handler {
	h := &Handler{auth: svc}
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(func(c *gin.Context) {
		start := time.Now()
		c.Next()
		logger.Info("request", "method", c.Request.Method, "path", c.FullPath(), "status", c.Writer.Status(), "duration_ms", time.Since(start).Milliseconds())
	})
	r.GET("/health/live", func(c *gin.Context) { c.JSON(200, gin.H{"status": "ok"}) })
	r.GET("/health/ready", func(c *gin.Context) {
		if err := svc.Ready(c.Request.Context()); err != nil {
			fail(c, 503, "unavailable", "database unavailable")
			return
		}
		c.JSON(200, gin.H{"status": "ok"})
	})
	r.POST("/auth/register", h.register)
	r.POST("/auth/login", h.login)
	r.POST("/auth/refresh", h.refresh)
	protected := r.Group("/")
	protected.Use(h.requireAuth)
	protected.POST("auth/logout", h.logout)
	protected.GET("users/me", h.me)
	protected.PATCH("users/me", h.updateMe)
	r.GET("/users/:id", h.publicProfile)
	return r
}
func fail(c *gin.Context, status int, code, msg string) {
	c.AbortWithStatusJSON(status, gin.H{"code": code, "message": msg})
}
func handleError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, services.ErrInvalidInput):
		fail(c, 400, "invalid_request", "invalid request")
	case errors.Is(err, services.ErrInvalidCredentials), errors.Is(err, services.ErrInvalidSession), errors.Is(err, services.ErrInvalidToken):
		fail(c, 401, "unauthorized", "invalid credentials or token")
	case errors.Is(err, services.ErrConflict):
		fail(c, 409, "conflict", "resource already exists")
	case errors.Is(err, services.ErrNotFound):
		fail(c, 404, "not_found", "resource not found")
	default:
		fail(c, 500, "internal", "internal server error")
	}
}
func (h *Handler) requireAuth(c *gin.Context) {
	raw := c.GetHeader("Authorization")
	if !strings.HasPrefix(raw, "Bearer ") {
		fail(c, 401, "unauthorized", "bearer token required")
		return
	}
	id, err := h.auth.VerifyAccess(strings.TrimPrefix(raw, "Bearer "))
	if err != nil {
		handleError(c, err)
		return
	}
	c.Set("user_id", id)
	c.Next()
}
func (h *Handler) register(c *gin.Context) {
	var in struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if c.ShouldBindJSON(&in) != nil {
		fail(c, 400, "invalid_request", "invalid JSON")
		return
	}
	u, err := h.auth.Register(c.Request.Context(), in.Username, in.Email, in.Password)
	if err != nil {
		handleError(c, err)
		return
	}
	c.JSON(201, u)
}
func (h *Handler) login(c *gin.Context) {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if c.ShouldBindJSON(&in) != nil {
		fail(c, 400, "invalid_request", "invalid JSON")
		return
	}
	tokens, err := h.auth.Login(c.Request.Context(), in.Email, in.Password)
	if err != nil {
		handleError(c, err)
		return
	}
	c.JSON(200, tokens)
}
func (h *Handler) refresh(c *gin.Context) {
	var in struct {
		RefreshToken string `json:"refresh_token"`
	}
	if c.ShouldBindJSON(&in) != nil {
		fail(c, 400, "invalid_request", "invalid JSON")
		return
	}
	tokens, err := h.auth.Refresh(c.Request.Context(), in.RefreshToken)
	if err != nil {
		handleError(c, err)
		return
	}
	c.JSON(200, tokens)
}
func (h *Handler) logout(c *gin.Context) {
	var in struct {
		RefreshToken string `json:"refresh_token"`
	}
	if c.ShouldBindJSON(&in) != nil {
		fail(c, 400, "invalid_request", "invalid JSON")
		return
	}
	if err := h.auth.Logout(c.Request.Context(), c.GetString("user_id"), in.RefreshToken); err != nil {
		handleError(c, err)
		return
	}
	c.Status(204)
}
func (h *Handler) me(c *gin.Context) {
	u, err := h.auth.Profile(c.Request.Context(), c.GetString("user_id"))
	if err != nil {
		handleError(c, err)
		return
	}
	c.JSON(200, u)
}
func (h *Handler) publicProfile(c *gin.Context) {
	u, err := h.auth.Profile(c.Request.Context(), c.Param("id"))
	if err != nil {
		handleError(c, err)
		return
	}
	c.JSON(200, gin.H{"id": u.ID, "username": u.Username})
}
func (h *Handler) updateMe(c *gin.Context) {
	var in struct {
		Username string `json:"username"`
	}
	if c.ShouldBindJSON(&in) != nil {
		fail(c, 400, "invalid_request", "invalid JSON")
		return
	}
	u, err := h.auth.UpdateProfile(c.Request.Context(), c.GetString("user_id"), in.Username)
	if err != nil {
		handleError(c, err)
		return
	}
	c.JSON(200, u)
}
