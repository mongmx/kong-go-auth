package user

import (
	"errors"
	"log"
	"net/http"

	"github.com/go-playground/validator"
	"github.com/jmoiron/sqlx"
	"github.com/labstack/echo/v4"
)

// Handler - HTTP auth handler.
type Handler struct {
	db        *sqlx.DB
	kong      *Kong
	validator *validator.Validate
}

// NewHandler - a factory function of auth handler.
func NewHandler(db *sqlx.DB, kong *Kong, validator *validator.Validate) *Handler {
	return &Handler{
		db:        db,
		kong:      kong,
		validator: validator,
	}
}

func (h Handler) postRegister(c echo.Context) error {
	reqBody := ReqBody{}
	err := c.Bind(&reqBody)
	if err != nil {
		return ErrorResponse(c, http.StatusBadRequest, err)
	}
	err = reqBody.validate(h.validator)
	if err != nil {
		return ErrorResponse(c, http.StatusBadRequest, err)
	}

	user := &User{
		Email:    reqBody.Data.Email,
		Password: reqBody.Data.hashPassword(),
	}
	err = user.create(h.db)
	if err != nil {
		return ErrorResponse(c, http.StatusInternalServerError, err)
	}

	jwtCredentials, err := h.kong.CreateConsumerCredentials(user)
	if err != nil {
		return ErrorResponse(c, http.StatusInternalServerError, err)
	}

	err = user.updateCredentials(h.db, jwtCredentials)
	if err != nil {
		log.Println(err)
		return ErrorResponse(c, http.StatusInternalServerError, err)
	}

	token, err := h.kong.GenerateJWT(jwtCredentials)
	if err != nil {
		return ErrorResponse(c, http.StatusInternalServerError, err)
	}

	return SuccessResponse(c, CredentialsResponse(user.ID, token))
}

func (h Handler) postAuthen(c echo.Context) error {
	reqBody := ReqBody{}
	err := c.Bind(&reqBody)
	if err != nil {
		return ErrorResponse(c, http.StatusBadRequest, err)
	}
	err = reqBody.validate(h.validator)
	if err != nil {
		return ErrorResponse(c, http.StatusBadRequest, err)
	}

	user := User{
		Email:    reqBody.Data.Email,
		Password: reqBody.Data.hashPassword(),
	}

	jwtCredentials, passwordHash, err := user.findByEmail(h.db)
	if err != nil {
		return ErrorResponse(c, http.StatusNotFound, errors.New("user not found"))
	}

	if !reqBody.Data.passwordMatches(passwordHash) {
		return ErrorResponse(c, http.StatusNotFound, errors.New("user not found"))
	}

	token, err := h.kong.GenerateJWT(jwtCredentials)
	if err != nil {
		return ErrorResponse(c, http.StatusInternalServerError, err)
	}
	return SuccessResponse(c, CredentialsResponse(reqBody.Data.ID, token))
}

func (h Handler) postRefreshToken(c echo.Context) error {
	// TODO: implement this
	// jwtCredentials, err := user.findByRefreshToken(h.db)
	// if err != nil {
	// 	return ErrorResponse(c, http.StatusNotFound, errors.New("token not found"))
	// }
	// token, err := h.kong.GenerateJWT(jwtCredentials)
	// if err != nil {
	// 	return ErrorResponse(c, http.StatusInternalServerError, err)
	// }
	// return SuccessResponse(c, CredentialsResponse(reqBody.Data.ID, token))
	return nil
}

func (h Handler) getProfile(c echo.Context) error {
	return SuccessResponse(c, map[string]interface{}{
		"status": "authen success",
	})
}