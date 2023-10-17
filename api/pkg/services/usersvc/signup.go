package usersvc

import (
	"fmt"

	"github.com/GDGVIT/configgy-backend/api/pkg"
	"github.com/GDGVIT/configgy-backend/api/pkg/api"
	"github.com/GDGVIT/configgy-backend/api/pkg/database"
	"github.com/labstack/echo/v4"
)

func (svc *UserSvcImpl) SignUp(c echo.Context, req api.SignupRequest) error {

	// print the email and password
	if req.Email != nil {
		fmt.Println(*req.Email)
	}

	if req.Password != nil {
		fmt.Println(*req.Password)
	}

	// perform signup logic here
	user := pkg.User{
		Email:    string(*req.Email),
		Password: *req.Password,
	}

	// get the db connection
	db, _ := database.Connection()
	tx := db.Create(&user)
	if tx.Error != nil {
		return tx.Error
	}

	return nil
}
