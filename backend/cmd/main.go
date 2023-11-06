package main

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/EvgeniyBudaev/golang-react-oauth--flow/backend/procon_data"
	"github.com/gorilla/mux"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

var home_tpl = template.Must(template.ParseFiles("./templates/index.html"))
var systems_tpl = template.Must(template.ParseFiles("./templates/index.html", "./templates/systems.html"))
var addr = flag.String("addr", "0.0.0.0:8000", "http service address")

var config = struct {
	clientId                       string
	clientSecret                   string
	authUrl                        string
	authCodeCallback               string
	logoutUrl                      string
	afterLogoutRedirect            string
	appTokenValidationClient       string
	appTokenValidationClientSecret string
	tokenEndpoint                  string
	validateToken                  string
}{
	clientId:                       "goreact-client",
	clientSecret:                   "yVURt5DaySVPZYps5lRzvcIPTXtGhmrJ",
	authUrl:                        "http://localhost:8181/realms/goreact-realm/protocol/openid-connect/auth",
	authCodeCallback:               "http://localhost:8000/authCodeRedirect",
	logoutUrl:                      "http://localhost:8181/realms/goreact-realm/protocol/openid-connect/logout",
	afterLogoutRedirect:            "http://localhost:8000",
	appTokenValidationClient:       "TestingAppTokenValidationClient",
	appTokenValidationClientSecret: "yVURt5DaySVPZYps5lRzvcIPTXtGhmrJ",
	tokenEndpoint:                  "http://localhost:8181/realms/goreact-realm/protocol/openid-connect/token",
	validateToken:                  "http://localhost:8181/realms/goreact-realm/protocol/openid-connect/token/introspect",
}

type AppVars struct {
	AuthCode     string
	SessionState string
	AccessToken  string
	RefreshToken string
	Scope        string
	Systems      []struct {
		Host string `json:"host"`
		Port string `json:"port"`
	} `json:"systems"`
}

var appVars = AppVars{}

func home(w http.ResponseWriter, r *http.Request) {
	home_tpl.Execute(w, appVars)
}

func login(w http.ResponseWriter, r *http.Request) {
	req, err := http.NewRequest("GET", config.authUrl, nil)
	if err != nil {
		fmt.Println(err)
	} else {
		qp := url.Values{}
		qp.Add("state", "noop")
		qp.Add("client_id", config.clientId)
		qp.Add("response_type", "code")
		qp.Add("redirect_uri", config.authCodeCallback)
		req.URL.RawQuery = qp.Encode()
		http.Redirect(w, r, req.URL.String(), http.StatusFound)
	}
}

func logout(w http.ResponseWriter, r *http.Request) {
	q := url.Values{}
	q.Add("redirect_uri", config.afterLogoutRedirect)
	logoutUrl, err := url.Parse(config.logoutUrl)
	logoutUrl.RawQuery = q.Encode()
	// clear session values
	appVars = AppVars{}
	if err != nil {
		fmt.Println("err parsing logout url")
	} else {
		http.Redirect(w, r, logoutUrl.String(), http.StatusFound)
	}
}

func authCodeRedirect(w http.ResponseWriter, r *http.Request) {
	appVars.AuthCode = r.URL.Query().Get("code")
	appVars.SessionState = r.URL.Query().Get("session_state")
	r.URL.RawQuery = ""
	fmt.Println("Req: %+v \n", appVars)
	http.Redirect(w, r, "http://localhost:8000", http.StatusFound)
}

func exchangeToken(w http.ResponseWriter, r *http.Request) {
	form := url.Values{}
	form.Add("grant_type", "authorization_code")
	form.Add("code", appVars.AuthCode)
	form.Add("redirect_uri", config.authCodeCallback)
	form.Add("client_id", config.clientId)
	req, err := http.NewRequest("POST", config.tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		fmt.Println("Error initializing exchange request")
	} else {
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(config.clientId, config.clientSecret)
		c := http.Client{}
		res, err := c.Do(req)
		defer res.Body.Close()
		if err != nil {
			fmt.Println("Error with doing access token request")
		} else {
			data, err := ioutil.ReadAll(res.Body)
			if err != nil {
				fmt.Println("Error reading access token response")
			} else {
				at := &procon_data.AccessToken{}
				json.Unmarshal(data, at)
				appVars.AccessToken = at.AccessToken
				appVars.RefreshToken = at.RefreshToken
				appVars.Scope = at.Scope
				home_tpl.Execute(w, appVars)
			}
		}
	}
}

func extractToken(r *http.Request) (string, error) {
	//Get Token From Headers
	header_token := r.Header.Get("Authorization")
	//Get Token From Body
	body_token := r.FormValue("access_token")
	//From Query Param
	query_token := r.URL.Query().Get("access_token")
	switch {
	case header_token != "":
		split_auth_header := strings.Split(header_token, " ")
		if len(split_auth_header) != 2 {
			return "", fmt.Errorf("invalid Authorization header format")
		}
		header_token = split_auth_header[1]
		if header_token != "" {
			return header_token, nil
		}
		break
	case body_token != "":
		return body_token, nil
		break
	case query_token != "":
		return query_token, nil
		break
	default:
		return "", fmt.Errorf("No Access token")
		break
	}
	return "", fmt.Errorf("No Access token")
}

func validateToken(token string) bool {
	form := url.Values{}
	form.Add("token", token)
	form.Add("token_type_hint", "requesting_party_token")
	req, err := http.NewRequest("POST", config.validateToken, strings.NewReader(form.Encode()))
	if err != nil {
		fmt.Println(err)
	} else {
		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(config.appTokenValidationClient, config.appTokenValidationClientSecret)
		c := http.Client{}
		res, err := c.Do(req)
		if err != nil {
			fmt.Println(err)
		} else {
			data, err := ioutil.ReadAll(res.Body)
			defer res.Body.Close()
			if err != nil {
				fmt.Println(err)
			} else {
				//fmt.Println(string(data))
				introSpect := procon_data.TokenIntrospect{}
				err = json.Unmarshal(data, introSpect)
				if err != nil {
					fmt.Println(err)
					return false
				} else {
					//fmt.Println("INTROSPECT-RESULT: ", introSpect.Active)
					return introSpect.Active
				}
			}
		}
	}
	return false
}

func extractValidateClaims(token string) bool {
	tokenParts := strings.Split(token, ".")
	claim, err := base64.RawURLEncoding.DecodeString(tokenParts[1])
	if err != nil {
		fmt.Println(err)
		return false
	}
}

func apiResourceSystems(w http.ResponseWriter, r *http.Request) {
	hiveData := []byte(``)
	//Validate JWT
	token, err := extractToken(r)
	if err != nil {
		fmt.Println(err)
		hiveData = []byte(`[{"host":"Error","port":"Invalid Token @Extract"}]`)
	} else {
		if !validateToken(token) {
			hiveData = []byte(`[{"host":"Error","port":"Invalid Token @Validate"}]`)
		} else {
			//lets check scopes && Audience
			if !extractValidateClaims(token) {
				hiveData = []byte(`[{"host":"Error","port":"Invalid Token @ValidateClaims"}]`)
			} else {
				//Okay all checks pass
				hiveData = []byte(`[
		{
			"host":"localhost",
			"port":"8080"
		},
	]`)
			}
		}
	}
	w.Header().Add("Content-Type", "application/json")
	w.Header().Add("Access-Control-Allow-Origin", "*")
	w.Write(hiveData)
}

func getSystems(w http.ResponseWriter, r *http.Request) {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	req, err := http.NewRequest("GET", "http://localhost:8000/api/resource/systems", nil)
	if err != nil {
		fmt.Println(err)
	} else {
		req.Header.Add("Authorization", "Bearer "+appVars.AccessToken)
		c := http.Client{}
		res, err := c.Do(req)
		if err != nil {
			fmt.Println("Error with Req @ getSystems ", err)
		} else {
			data, err := ioutil.ReadAll(res.Body)
			if err != nil {
				fmt.Println("Error Reading Result @getSystems ", err)
			} else {
				hive := procon_data.Hive{}
				err := json.Unmarshal(data, &hive.Systems)
				if err != nil {
					fmt.Println("Error unpacking data to object @getSystems ", err)
				} else {
					appVars.Systems = hive.Systems
					fmt.Println(appVars.Systems)
					systems_tpl.Execute(w, appVars)
					return //so template doesn't get executed twice
				}
			}
		}
	}
	systems_tpl.Execute(w, appVars) //catch for all errors
}

func main() {
	fmt.Println("Initializing Server...")
	r := mux.NewRouter()

	r.HandleFunc("/", home)
	r.HandleFunc("/login", login)
	r.HandleFunc("/logout", logout)
	r.HandleFunc("/authCodeRedirect", authCodeRedirect)
	r.HandleFunc("/exchange", exchangeToken)

	//Client app route
	r.HandleFunc("/systems", getSystems)

	//Act as Resource Server Route
	r.HandleFunc("/api/resource/systems", apiResourceSystems)

	fmt.Println("Server running on port: 8000")
	http.ListenAndServe(*addr, r)
}
