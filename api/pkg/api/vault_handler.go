package api

import (
	"context"
	"net/http"

	"github.com/labstack/echo/v4"
)

type VaultService interface {
	VaultCreate(c context.Context, req VaultCreateRequest, userPID string) (GenericMessageResponse, int, error)
	VaultGet(c context.Context, vaultPID string, userPID string) (VaultCreateRequest, int, error)
	VaultEdit(c context.Context, vaultPID string, req VaultEditRequest, userPID string) (GenericMessageResponse, int, error)
	VaultDelete(c context.Context, vaultPID string, userPID string) (GenericMessageResponse, int, error)
	VaultList(c context.Context, userPID string) (VaultListResponse, int, error)
}

// VaultCreate - VaultCreate
// (POST /vault/create)
func (svc *Service) VaultCreate(c echo.Context) error {
	svc.logger.Info("Vault creation request received")
	userPID, err := getUserPIDFromAuthToken(c)
	if err != nil {
		svc.logger.Error("Failed to get user PID from auth token:", err)
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid authorization header")
	}
	// Parse the request body into the VaultCreate struct
	request := &VaultCreateRequest{}
	if err := c.Bind(request); err != nil {
		svc.logger.Error("Failed to parse request body:", err)
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body format")
	}

	// You can now perform your vault creation logic here
	response, httpCode, err := svc.Services.VaultSvc.VaultCreate(c.Request().Context(), *request, userPID)
	if err != nil {
		svc.logger.Error("Failed to create vault:", err)
		return echo.NewHTTPError(httpCode, "Failed to create vault")
	}
	// Return a response (e.g., a success message)
	return c.JSON(http.StatusOK, response)
}

// VaultDelete - VaultDelete
// (DELETE /vault/{id})
func (svc *Service) VaultDelete(c echo.Context, vaultPID string) error {
	userPID, err := getUserPIDFromAuthToken(c)
	if err != nil {
		svc.logger.Error("Failed to get user PID from auth token:", err)
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid authorization header")
	}

	response, httpCode, err := svc.Services.VaultSvc.VaultDelete(svc.ctx, vaultPID, userPID)
	if err != nil {
		svc.logger.Error("Failed to delete vault:", err)
		return echo.NewHTTPError(httpCode, "Failed to delete vault")
	}
	svc.logger.Info("Vault delete request received")

	// Return a response (e.g., a success message)
	return c.JSON(http.StatusOK, response)
}

// VaultEdit - VaultEdit
// (POST /vault/edit/{id})
func (svc *Service) VaultEdit(c echo.Context, vaultPID string) error {
	userPID, err := getUserPIDFromAuthToken(c)
	if err != nil {
		svc.logger.Error("Failed to get user PID from auth token:", err)
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid authorization header")
	}
	// Parse the request body into the SignupRequest struct
	request := &VaultEditRequest{}
	if err := c.Bind(request); err != nil {
		svc.logger.Error("Failed to parse request body:", err)
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body format")
	}

	// You can now perform your vault edit logic here
	response, httpCode, err := svc.Services.VaultSvc.VaultEdit(c.Request().Context(), vaultPID, *request, userPID)
	if err != nil {
		svc.logger.Error("Failed to signup:", err)
		return echo.NewHTTPError(httpCode, "Failed to signup")
	}
	svc.logger.Info("Signup request received")

	// Return a response (e.g., a success message)
	return c.JSON(http.StatusOK, response)
}

// VaultGet - VaultGet
// (GET /vault/{id})
func (svc *Service) VaultGet(c echo.Context, vaultPID string) error {
	userPID, err := getUserPIDFromAuthToken(c)
	if err != nil {
		svc.logger.Error("Failed to get user PID from auth token:", err)
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid authorization header")
	}
	response, httpCode, err := svc.Services.VaultSvc.VaultGet(c.Request().Context(), vaultPID, userPID)
	if err != nil {
		svc.logger.Error("Failed to get vault:", err)
		return echo.NewHTTPError(httpCode, "Failed to get vault")
	}
	svc.logger.Info("Vault Get request received")

	// Return a response (e.g., a success message)
	return c.JSON(http.StatusOK, response)
}

// VaultList - VaultList
// (GET /vault/list)

func (svc *Service) VaultList(c echo.Context) error {
	userPID, err := getUserPIDFromAuthToken(c)
	if err != nil {
		svc.logger.Error("Failed to get user PID from auth token:", err)
		return echo.NewHTTPError(http.StatusUnauthorized, "Invalid authorization header")
	}
	response, httpCode, err := svc.Services.VaultSvc.VaultList(c.Request().Context(), userPID)
	if err != nil {
		svc.logger.Error("Failed to get vault list:", err)
		return echo.NewHTTPError(httpCode, "Failed to get vault list")
	}

	// Return a response (e.g., a success message)
	return c.JSON(http.StatusOK, response)
}
