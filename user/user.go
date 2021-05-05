package user

import (
	"encoding/json"

	"github.com/go-playground/validator"
	"github.com/jmoiron/sqlx"
	"github.com/kong/go-kong/kong"
	"golang.org/x/crypto/bcrypt"
)

type D map[string]interface{}

type ResponseData struct {
	Data interface{} `json:"data"`
}

type Data struct {
	ID       string `db:"id"`
	Email    string `json:"email" validate:"required,email" db:"email"`
	Password string `json:"password" validate:"required" db:"password"`
}

type ReqBody struct {
	Data Data `json:"data" validate:"required"`
}

type JSONErrs []error

func (d Data) hashPassword() string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(d.Password), bcrypt.MinCost)
	return string(hash)
}

func (d Data) passwordMatches(hashedPwd string) bool {
	byteHash := []byte(hashedPwd)
	err := bcrypt.CompareHashAndPassword(byteHash, []byte(d.Password))
	if err != nil {
		return false
	}
	return true
}

func (u ReqBody) validate(v *validator.Validate) error {
	return v.Struct(u)
}

type User struct {
	ID       string `db:"id"`
	Email    string `json:"email" validate:"required,email" db:"email"`
	Password string `json:"password" validate:"required" db:"password"`
}

func (u *User) hashPassword() string {
	hash, _ := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.MinCost)
	return string(hash)
}

func (u *User) create(db *sqlx.DB) error {
	err := db.QueryRow(
		"INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id",
		u.Email,
		u.hashPassword(),
	).Scan(&u.ID)
	if err != nil {
		return err
	}
	return nil
}

func (u *User) updateCredentials(db *sqlx.DB, jwtCredentials *kong.JWTAuth) error {
	jsonCredentials, err := json.Marshal(jwtCredentials)
	if err != nil {
		return err
	}
	_, err = db.Exec(
		"UPDATE users SET jwt_credentials = $2 WHERE id = $1",
		u.ID, jsonCredentials)
	if err != nil {
		return err
	}
	return nil
}

func (u *User) findByEmail(db *sqlx.DB) (*kong.JWTAuth, string, error) {
	jwtCredentials := new(kong.JWTAuth)
	var passwordHash string
	err := db.QueryRow(
		"SELECT id, email, password, jwt_credentials FROM users WHERE email = $1",
		u.Email,
	).Scan(&u.ID, &u.Email, &passwordHash, &jwtCredentials)
	if err != nil {
		return nil, "", err
	}
	return jwtCredentials, passwordHash, nil
}
