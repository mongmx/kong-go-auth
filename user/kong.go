package user

import (
	"context"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/kong/go-kong/kong"
)

// KongStatus returns the status of the kong server
type Kong struct {
	Host   string
	Port   string
	Client *kong.Client
}

func NewKong() *Kong {
	client, err := kong.NewClient(nil, http.DefaultClient)
	if err != nil {
		return nil
	}
	return &Kong{
		Host:   os.Getenv("KONG_HOST"),
		Port:   os.Getenv("KONG_ADMIN_PORT"),
		Client: client,
	}
}

type CustomClaims struct {
	Role string `json:"role"`
	jwt.StandardClaims
}

func (k Kong) GenerateJWT(jwtCredentials *kong.JWTAuth) (string, error) {
	expiresAt := time.Now().Add(time.Minute * 10).Unix()
	token := jwt.New(jwt.SigningMethodHS256)

	token.Claims = CustomClaims{
		"user",
		jwt.StandardClaims{
			ExpiresAt: expiresAt,
			Id:        *jwtCredentials.Consumer.ID,
			Issuer:    *jwtCredentials.Key,
		},
	}
	
	tokenString, err := token.SignedString([]byte(*jwtCredentials.Secret))
	if err != nil {
		return "", err
	}
	return tokenString, nil
}

func (k Kong) CreateConsumerCredentials(user *User) (*kong.JWTAuth, error) {
	userId := strings.Replace(user.ID, "-", "", -1)
	consumer, err := k.Client.Consumers.Create(context.Background(), &kong.Consumer{
		CustomID: &userId,
		Username: &user.Email,
	})
	if err != nil {
		return nil, err
	}
	jwtCredentials, err := k.Client.JWTAuths.Create(context.Background(), consumer.ID, &kong.JWTAuth{})
	if err != nil {
		return nil, err
	}
	return jwtCredentials, nil
}
