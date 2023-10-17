package api

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

type UserService interface {
	SignUp(c echo.Context, req SignupRequest) error
}

// SignUp - Signup
// (POST /user/signup)
func (svc *Service) Signup(c echo.Context) error {
	svc.logger.Info("Signup request received")

	// Parse the request body into the SignupRequest struct
	request := &SignupRequest{}
	if err := c.Bind(request); err != nil {
		svc.logger.Error("Failed to parse request body:", err)
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request body format")
	}

	// You can now perform your signup logic here
	err := svc.Services.UserSvc.SignUp(c, *request)
	if err != nil {
		svc.logger.Error("Failed to signup:", err)
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to signup")
	}

	// Return a response (e.g., a success message)
	return c.JSON(http.StatusOK, map[string]string{
		"message": "User signed up successfully",
	})
}
