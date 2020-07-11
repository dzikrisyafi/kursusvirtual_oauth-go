package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dzikrisyafi/kursusvirtual_utils-go/rest_errors"
	"github.com/mercadolibre/golang-restclient/rest"
)

const (
	headerXPublic    = "X-Public"
	headerXClientID  = "X-Client-Id"
	headerXCallerID  = "X-Caller-Id"
	paramAccessToken = "access_token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8000",
		Timeout: 200 * time.Millisecond,
	}
)

type accessToken struct {
	ID       string `json:"id"`
	UserID   int    `json:"user_id"`
	ClientID int    `json:"client_id"`
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerID(request *http.Request) int {
	if request == nil {
		return 0
	}
	callerID, err := strconv.Atoi(request.Header.Get(headerXCallerID))
	if err != nil {
		return 0
	}
	return callerID
}

func GetClientID(request *http.Request) int {
	if request == nil {
		return 0
	}
	clientID, err := strconv.Atoi(request.Header.Get(headerXClientID))
	if err != nil {
		return 0
	}
	return clientID
}

func AuthenticateRequest(request *http.Request) rest_errors.RestErr {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenId == "" {
		return nil
	}
	at, err := getAccessToken(accessTokenId)
	if err != nil {
		if err.Status() == http.StatusNotFound {
			return nil
		}
		return err
	}

	request.Header.Add(headerXClientID, fmt.Sprintf("%v", at.ClientID))
	request.Header.Add(headerXCallerID, fmt.Sprintf("%v", at.UserID))

	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}

	request.Header.Del(headerXClientID)
	request.Header.Del(headerXCallerID)
}

func getAccessToken(accessTokenId string) (*accessToken, rest_errors.RestErr) {
	response := oauthRestClient.Get(fmt.Sprintf("/oauth/access_token/%s", accessTokenId))

	if response == nil || response.Response == nil {
		return nil, rest_errors.NewInternalServerError("invalid rest client response when trying to get access token", errors.New("network timeout"))
	}

	if response.StatusCode > 299 {
		restErr, err := rest_errors.NewRestErrorFromBytes(response.Bytes())
		if err != nil {
			return nil, rest_errors.NewInternalServerError("invalid error interface when trying to get access token", err)
		}
		return nil, restErr
	}

	var at accessToken
	if err := json.Unmarshal(response.Bytes(), &at); err != nil {
		return nil, rest_errors.NewInternalServerError("error when trying to unmarshal access token response", errors.New("error processing json"))
	}
	return &at, nil
}
