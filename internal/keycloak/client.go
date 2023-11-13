// Package keycloak
// copied from https://github.com/mrparkers/terraform-provider-keycloak/blob/master/keycloak/keycloak_client.go
//
// for full provider configuration compatibility

package keycloak

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/hashicorp/go-version"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"golang.org/x/net/publicsuffix"
)

type (
	KeycloakClient struct {
		baseUrl           string
		realm             string
		clientCredentials *ClientCredentials
		httpClient        *http.Client
		initialLogin      bool
		userAgent         string
		version           *version.Version
		additionalHeaders map[string]string
		debug             bool
		redHatSSO         bool
	}

	ClientCredentials struct {
		ClientId     string
		ClientSecret string
		Username     string
		Password     string
		GrantType    string
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
	}

	SystemInfo struct {
		ServerVersion string `json:"version"`
	}

	ComponentType struct {
		Id string `json:"id"`
	}

	ProviderType struct {
		Internal  bool                `json:"internal"`
		Providers map[string]Provider `json:"providers"`
	}

	Provider struct {
	}

	Theme struct {
		Name    string   `json:"name"`
		Locales []string `json:"locales,omitempty"`
	}

	ServerInfo struct {
		SystemInfo     SystemInfo                 `json:"systemInfo"`
		ComponentTypes map[string][]ComponentType `json:"componentTypes"`
		ProviderTypes  map[string]ProviderType    `json:"providers"`
		Themes         map[string][]Theme         `json:"themes"`
	}

	ApiError struct {
		Code    int
		Message string
	}
)

const (
	apiUrl   = "/admin"
	tokenUrl = "%s/realms/%s/protocol/openid-connect/token"
)

// https://access.redhat.com/articles/2342881
var redHatSSO7VersionMap = map[int]string{
	6: "18.0.0",
	5: "15.0.6",
	4: "9.0.17",
}

func NewKeycloakClient(
	ctx context.Context,
	url, basePath, clientId, clientSecret, realm, username, password string,
	initialLogin bool,
	clientTimeout int,
	caCert string,
	tlsInsecureSkipVerify bool,
	userAgent string,
	redHatSSO bool,
	additionalHeaders map[string]string,
) (*KeycloakClient, error) {
	clientCredentials := &ClientCredentials{
		ClientId:     clientId,
		ClientSecret: clientSecret,
	}
	if password != "" && username != "" {
		clientCredentials.Username = username
		clientCredentials.Password = password
		clientCredentials.GrantType = "password"
	} else if clientSecret != "" {
		clientCredentials.GrantType = "client_credentials"
	} else {
		if initialLogin {
			return nil, fmt.Errorf("must specify client id, username and password for password grant, or client id and secret for client credentials grant")
		} else {
			tflog.Warn(ctx, "missing required keycloak credentials, but proceeding anyways as initial_login is false")
		}
	}

	httpClient, err := newHttpClient(tlsInsecureSkipVerify, clientTimeout, caCert)
	if err != nil {
		return nil, fmt.Errorf("failed to create http client: %v", err)
	}

	keycloakClient := KeycloakClient{
		baseUrl:           url + basePath,
		clientCredentials: clientCredentials,
		httpClient:        httpClient,
		initialLogin:      initialLogin,
		realm:             realm,
		userAgent:         userAgent,
		redHatSSO:         redHatSSO,
		additionalHeaders: additionalHeaders,
	}

	if keycloakClient.initialLogin {
		err = keycloakClient.login(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to perform initial login to Keycloak: %v", err)
		}
	}

	if tfLog, ok := os.LookupEnv("TF_LOG"); ok {
		if tfLog == "DEBUG" {
			keycloakClient.debug = true
		}
	}

	return &keycloakClient, nil
}

func (k *KeycloakClient) login(ctx context.Context) error {
	accessTokenUrl := fmt.Sprintf(tokenUrl, k.baseUrl, k.realm)
	accessTokenData := k.getAuthenticationFormData()

	tflog.Debug(ctx, "Login request", map[string]interface{}{
		"request": accessTokenData.Encode(),
	})

	accessTokenRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, accessTokenUrl, strings.NewReader(accessTokenData.Encode()))
	if err != nil {
		return err
	}

	for header, value := range k.additionalHeaders {
		accessTokenRequest.Header.Set(header, value)
	}

	accessTokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if k.userAgent != "" {
		accessTokenRequest.Header.Set("User-Agent", k.userAgent)
	}

	accessTokenResponse, err := k.httpClient.Do(accessTokenRequest)
	if err != nil {
		return err
	}
	if accessTokenResponse.StatusCode != http.StatusOK {
		return fmt.Errorf("error sending POST request to %s: %s", accessTokenUrl, accessTokenResponse.Status)
	}

	defer accessTokenResponse.Body.Close()

	body, _ := ioutil.ReadAll(accessTokenResponse.Body)

	tflog.Debug(ctx, "Login response", map[string]interface{}{
		"response": string(body),
	})

	var clientCredentials ClientCredentials
	err = json.Unmarshal(body, &clientCredentials)
	if err != nil {
		return err
	}

	k.clientCredentials.AccessToken = clientCredentials.AccessToken
	k.clientCredentials.RefreshToken = clientCredentials.RefreshToken
	k.clientCredentials.TokenType = clientCredentials.TokenType

	info, err := k.GetServerInfo(ctx)
	if err != nil {
		return err
	}

	serverVersion := info.SystemInfo.ServerVersion
	if strings.Contains(serverVersion, ".GA") {
		serverVersion = strings.ReplaceAll(info.SystemInfo.ServerVersion, ".GA", "")
	}

	v, err := version.NewVersion(serverVersion)
	if err != nil {
		return err
	}

	if k.redHatSSO {
		keycloakVersion, err := version.NewVersion(redHatSSO7VersionMap[v.Segments()[1]])
		if err != nil {
			return err
		}

		k.version = keycloakVersion
	} else {
		k.version = v
	}

	return nil
}

func (k *KeycloakClient) refresh(ctx context.Context) error {
	refreshTokenUrl := fmt.Sprintf(tokenUrl, k.baseUrl, k.realm)
	refreshTokenData := k.getAuthenticationFormData()

	tflog.Debug(ctx, "Refresh request", map[string]interface{}{
		"request": refreshTokenData.Encode(),
	})

	refreshTokenRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, refreshTokenUrl, strings.NewReader(refreshTokenData.Encode()))
	if err != nil {
		return err
	}

	for header, value := range k.additionalHeaders {
		refreshTokenRequest.Header.Set(header, value)
	}

	refreshTokenRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if k.userAgent != "" {
		refreshTokenRequest.Header.Set("User-Agent", k.userAgent)
	}

	refreshTokenResponse, err := k.httpClient.Do(refreshTokenRequest)
	if err != nil {
		return err
	}

	defer refreshTokenResponse.Body.Close()

	body, _ := ioutil.ReadAll(refreshTokenResponse.Body)

	tflog.Debug(ctx, "Refresh response", map[string]interface{}{
		"response": string(body),
	})

	// Handle 401 "User or client no longer has role permissions for client key" until I better understand why that happens in the first place
	if refreshTokenResponse.StatusCode == http.StatusBadRequest {
		tflog.Debug(ctx, "Unexpected 400, attempting to log in again")

		return k.login(ctx)
	}

	var clientCredentials ClientCredentials
	err = json.Unmarshal(body, &clientCredentials)
	if err != nil {
		return err
	}

	k.clientCredentials.AccessToken = clientCredentials.AccessToken
	k.clientCredentials.RefreshToken = clientCredentials.RefreshToken
	k.clientCredentials.TokenType = clientCredentials.TokenType

	return nil
}

func (k *KeycloakClient) getAuthenticationFormData() url.Values {
	authenticationFormData := url.Values{}
	authenticationFormData.Set("client_id", k.clientCredentials.ClientId)
	authenticationFormData.Set("grant_type", k.clientCredentials.GrantType)

	if k.clientCredentials.GrantType == "password" {
		authenticationFormData.Set("username", k.clientCredentials.Username)
		authenticationFormData.Set("password", k.clientCredentials.Password)

		if k.clientCredentials.ClientSecret != "" {
			authenticationFormData.Set("client_secret", k.clientCredentials.ClientSecret)
		}

	} else if k.clientCredentials.GrantType == "client_credentials" {
		authenticationFormData.Set("client_secret", k.clientCredentials.ClientSecret)
	}

	return authenticationFormData
}

func (k *KeycloakClient) addRequestHeaders(request *http.Request) {
	tokenType := k.clientCredentials.TokenType
	accessToken := k.clientCredentials.AccessToken

	for header, value := range k.additionalHeaders {
		request.Header.Set(header, value)
	}

	request.Header.Set("Authorization", fmt.Sprintf("%s %s", tokenType, accessToken))
	request.Header.Set("Accept", "application/json")

	if k.userAgent != "" {
		request.Header.Set("User-Agent", k.userAgent)
	}

	if request.Method == http.MethodPost || request.Method == http.MethodPut || request.Method == http.MethodDelete {
		request.Header.Set("Content-type", "application/json")
	}
}

/*
*
Sends an HTTP request and refreshes credentials on 403 or 401 errors
*/
func (k *KeycloakClient) sendRequest(ctx context.Context, request *http.Request, body []byte) ([]byte, string, error) {
	if !k.initialLogin {
		k.initialLogin = true
		err := k.login(ctx)
		if err != nil {
			return nil, "", fmt.Errorf("error logging in: %s", err)
		}
	}

	requestMethod := request.Method
	requestPath := request.URL.Path

	requestLogArgs := map[string]interface{}{
		"method": requestMethod,
		"path":   requestPath,
	}

	if body != nil {
		request.Body = ioutil.NopCloser(bytes.NewReader(body))
		requestLogArgs["body"] = string(body)
	}

	tflog.Debug(ctx, "Sending request", requestLogArgs)

	k.addRequestHeaders(request)

	response, err := k.httpClient.Do(request)
	if err != nil {
		return nil, "", fmt.Errorf("error sending request: %v", err)
	}

	// Unauthorized: Token could have expired
	// Forbidden: After creating a realm, following GETs for the realm return 403 until you refresh
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		tflog.Debug(ctx, "Got unexpected response, attempting refresh", map[string]interface{}{
			"status": response.Status,
		})

		err := k.refresh(ctx)
		if err != nil {
			return nil, "", fmt.Errorf("error refreshing credentials: %s", err)
		}

		k.addRequestHeaders(request)

		if body != nil {
			request.Body = ioutil.NopCloser(bytes.NewReader(body))
		}
		response, err = k.httpClient.Do(request)
		if err != nil {
			return nil, "", fmt.Errorf("error sending request after refresh: %v", err)
		}
	}

	defer response.Body.Close()

	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, "", err
	}

	responseLogArgs := map[string]interface{}{
		"status": response.Status,
	}

	if len(responseBody) != 0 && request.URL.Path != "/auth/admin/serverinfo" {
		responseLogArgs["body"] = string(responseBody)
	}

	tflog.Debug(ctx, "Received response", responseLogArgs)

	if response.StatusCode >= 400 {
		errorMessage := fmt.Sprintf("error sending %s request to %s: %s.", request.Method, request.URL.Path, response.Status)

		if len(responseBody) != 0 {
			errorMessage = fmt.Sprintf("%s Response body: %s", errorMessage, responseBody)
		}

		return nil, "", &ApiError{
			Code:    response.StatusCode,
			Message: errorMessage,
		}
	}

	return responseBody, response.Header.Get("Location"), nil
}

func (k *KeycloakClient) get(ctx context.Context, path string, resource interface{}, params map[string]string) error {
	body, err := k.getRaw(ctx, k.baseUrl+path, params)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, resource)
}

func (k *KeycloakClient) getRaw(ctx context.Context, path string, params map[string]string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	if params != nil {
		query := url.Values{}
		for k, v := range params {
			query.Add(k, v)
		}
		request.URL.RawQuery = query.Encode()
	}

	body, _, err := k.sendRequest(ctx, request, nil)
	return body, err
}

func (k *KeycloakClient) sendRaw(ctx context.Context, path string, requestBody []byte) ([]byte, error) {
	resourceUrl := k.baseUrl + apiUrl + path

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, resourceUrl, nil)
	if err != nil {
		return nil, err
	}

	body, _, err := k.sendRequest(ctx, request, requestBody)

	return body, err
}

func (k *KeycloakClient) post(ctx context.Context, path string, requestBody interface{}) ([]byte, string, error) {
	resourceUrl := k.baseUrl + path

	payload, err := k.marshal(requestBody)
	if err != nil {
		return nil, "", err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, resourceUrl, nil)
	if err != nil {
		return nil, "", err
	}

	body, location, err := k.sendRequest(ctx, request, payload)

	return body, location, err
}

func (k *KeycloakClient) put(ctx context.Context, path string, requestBody interface{}) error {
	resourceUrl := k.baseUrl + path

	payload, err := k.marshal(requestBody)
	if err != nil {
		return err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPut, resourceUrl, nil)
	if err != nil {
		return err
	}

	_, _, err = k.sendRequest(ctx, request, payload)

	return err
}

func (k *KeycloakClient) delete(ctx context.Context, path string, requestBody interface{}) error {
	resourceUrl := k.baseUrl + path

	var (
		payload []byte
		err     error
	)

	if requestBody != nil {
		payload, err = k.marshal(requestBody)
		if err != nil {
			return err
		}
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, resourceUrl, nil)
	if err != nil {
		return err
	}

	_, _, err = k.sendRequest(ctx, request, payload)

	return err
}

func (k *KeycloakClient) marshal(body interface{}) ([]byte, error) {
	if k.debug {
		return json.MarshalIndent(body, "", "    ")
	}

	return json.Marshal(body)
}

func newHttpClient(tlsInsecureSkipVerify bool, clientTimeout int, caCert string) (*http.Client, error) {
	cookieJar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: tlsInsecureSkipVerify},
		Proxy:           http.ProxyFromEnvironment,
	}

	if caCert != "" {
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM([]byte(caCert))
		transport.TLSClientConfig.RootCAs = caCertPool
	}

	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 1
	retryClient.RetryWaitMin = time.Second * 1
	retryClient.RetryWaitMax = time.Second * 3

	httpClient := retryClient.StandardClient()
	httpClient.Timeout = time.Second * time.Duration(clientTimeout)
	httpClient.Transport = transport
	httpClient.Jar = cookieJar

	return httpClient, nil
}

func (k *KeycloakClient) GetServerInfo(ctx context.Context) (*ServerInfo, error) {
	var serverInfo ServerInfo

	err := k.get(ctx, apiUrl+"/serverinfo", &serverInfo, nil)
	if err != nil {
		return nil, err
	}

	return &serverInfo, nil
}

func (e *ApiError) Error() string {
	return e.Message
}

func ErrorIs404(err error) bool {
	keycloakError, ok := errwrap.GetType(err, &ApiError{}).(*ApiError)

	return ok && keycloakError != nil && keycloakError.Code == http.StatusNotFound
}

func ErrorIs409(err error) bool {
	keycloakError, ok := errwrap.GetType(err, &ApiError{}).(*ApiError)

	return ok && keycloakError != nil && keycloakError.Code == http.StatusConflict
}
