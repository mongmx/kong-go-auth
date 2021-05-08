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
	ID                   string                 `json:"-" db:"id"`
	Email                string                 `json:"email" validate:"required,email" db:"email"`
	Password             string                 `json:"password" validate:"required" db:"password"`
	JsonOauth2Credential string                 `json:"-" db:"oauth2_credentials"`
	Oauth2Credential     *kong.Oauth2Credential `json:"-" db:"-"`
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

func (u *User) updateCredentials(db *sqlx.DB, oauth2Credential *kong.Oauth2Credential) error {
	jsonCredentials, err := json.Marshal(oauth2Credential)
	if err != nil {
		return err
	}
	_, err = db.Exec(
		"UPDATE users SET oauth2_credentials = $2 WHERE id = $1",
		u.ID, jsonCredentials)
	if err != nil {
		return err
	}
	return nil
}

func (u *User) updateRefreshToken(db *sqlx.DB, token *Oauth2Token) error {
	_, err := db.Exec(
		"UPDATE users SET oauth2_refresh_token = $2 WHERE id = $1",
		u.ID, token.RefreshToken)
	if err != nil {
		return err
	}
	return nil
}

func (u *User) findByEmail(db *sqlx.DB) (string, error) {
	var oauth2CredentialStr string
	var passwordHash string
	err := db.QueryRow(
		"SELECT id, email, password, oauth2_credentials FROM users WHERE email = $1",
		u.Email,
	).Scan(&u.ID, &u.Email, &passwordHash, &oauth2CredentialStr)
	if err != nil {
		return "", err
	}
	err = json.Unmarshal([]byte(oauth2CredentialStr), &u.Oauth2Credential)
	if err != nil {
		return "", err
	}
	return passwordHash, nil
}

func (u *User) findByRefreshToken(db *sqlx.DB, refreshToken string) error {
	var oauth2CredentialStr string
	err := db.QueryRow(
		"SELECT id, email, oauth2_credentials FROM users WHERE oauth2_refresh_token LIKE '%' || $1 || '%'",
		u.Email,
	).Scan(&u.ID, &u.Email, &refreshToken)
	if err != nil {
		return err
	}
	err = json.Unmarshal([]byte(oauth2CredentialStr), &u.Oauth2Credential)
	if err != nil {
		return err
	}
	return nil
}
