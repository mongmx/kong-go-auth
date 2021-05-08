package user

import (
	"net/http"

	"github.com/go-playground/validator"
	"github.com/jmoiron/sqlx"
	"github.com/labstack/echo/v4"
)

func Routes(e *echo.Echo, db *sqlx.DB) {
	k := NewKong()
	v := validator.New()
	h := NewHandler(db, k, v)
	e.POST("/register", h.postRegister)
	e.POST("/login", h.postAuthen)
	e.GET("/profile", h.getProfile)
}

func SuccessResponse(c echo.Context, r interface{}) error {
	return c.JSON(http.StatusOK, ResponseData{Data: r})
}

func ErrorResponse(c echo.Context, s int, r error) error {
	return c.JSON(s, ResponseData{Data: JSONErrs([]error{r})})
}

func CredentialsResponse(id string, oauth2Token *Oauth2Token) map[string]interface{} {
	return D{
		"account_id": id,
		"credentials": D{
			"oauth2": oauth2Token,
		},
	}
}