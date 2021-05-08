package user

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/kong/go-kong/kong"
)

type Oauth2Token struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Expires_in   int64  `json:"expires_in"`
}

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

func (k Kong) CreateConsumerCredentials(user *User) (*kong.Oauth2Credential, error) {
	userId := strings.Replace(user.ID, "-", "", -1)
	consumer, err := k.Client.Consumers.Create(context.Background(), &kong.Consumer{
		CustomID: &userId,
		Username: &user.Email,
	})
	if err != nil {
		return nil, err
	}
	appName := os.Getenv("APP_NAME")
	if appName == "" {
		appName = "go-service"
	}
	redirectURI := "http://127.0.0.1/callback"
	oauth2Credential, err := k.Client.Oauth2Credentials.Create(
		context.Background(),
		consumer.ID,
		&kong.Oauth2Credential{
			Name: &appName,
			// ClientID:     &user.Oauth2ClientID,
			// ClientSecret: &user.Oauth2ClientSecret,
			RedirectURIs: []*string{&redirectURI},
		},
	)
	if err != nil {
		return nil, err
	}
	log.Printf("%+v, %+v", *oauth2Credential.ClientID, *oauth2Credential.ClientSecret)
	k.CreateOauth2Token(user)
	return oauth2Credential, nil
}

func (k Kong) CreateOauth2Token(user *User) (*Oauth2Token, error) {
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	res, err := httpClient.PostForm(
		"https://127.0.0.1:443/oauth2/token",
		url.Values{
			"grant_type":           []string{"password"},
			"provision_key":        []string{"fDYMWzRURK4iGCuq8RbXsCXDiQsjhSu8"},
			"authenticated_userid": []string{user.ID},
			"client_id":            []string{*user.Oauth2Credential.ClientID},
			"client_secret":        []string{*user.Oauth2Credential.ClientSecret},
		},
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	bytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	oauth2Token := new(Oauth2Token)
	err = json.Unmarshal(bytes, &oauth2Token)
	if err != nil {
		return nil, err
	}
	log.Printf("%+v", oauth2Token)
	return oauth2Token, nil
}

func (k Kong) RefreshOauth2Token(user *User, refreshToken string) (*Oauth2Token, error) {
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	res, err := httpClient.PostForm(
		"https://127.0.0.1:443/oauth2/token",
		url.Values{
			"grant_type":    []string{"refresh_token"},
			"provision_key": []string{"fDYMWzRURK4iGCuq8RbXsCXDiQsjhSu8"},
			"refresh_token": []string{refreshToken},
			"client_id":     []string{*user.Oauth2Credential.ClientID},
			"client_secret": []string{*user.Oauth2Credential.ClientSecret},
		},
	)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	bytes, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	oauth2Token := new(Oauth2Token)
	err = json.Unmarshal(bytes, &oauth2Token)
	if err != nil {
		return nil, err
	}
	log.Printf("%+v", oauth2Token)
	return oauth2Token, nil
}
