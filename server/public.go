package server

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"

	"github.com/gorilla/sessions"
	log "github.com/sirupsen/logrus"

	"github.com/sklirg/letmein/auth"
)

// HTTP contains the internal variables for the server
// E.g. the database connection, session cookie name.
type HTTP struct {
	store                 *sessions.CookieStore
	CookieName            string
	CookieDomain          string
	LoginURL              string
	loginHTMLTemplate     *template.Template
	adminHTMLTemplate     *template.Template
	profileHTMLTemplate   *template.Template
	authorizeHTMLTemplate *template.Template
	authDB                *auth.Context
	grants                map[string][]*auth.Claim
}

// HandleAuth handles the incoming proxy auth request
func (context *HTTP) HandleAuth(w http.ResponseWriter, r *http.Request) {
	session, _ := context.store.Get(r, "letmein-session")

	// Make sure we have the required parameters for authorizing the request
	if len(r.Header["X-Forwarded-Proto"]) != 1 ||
		len(r.Header["X-Forwarded-Host"]) != 1 ||
		len(r.Header["X-Forwarded-Uri"]) != 1 {
		log.Debug("Missing required headers")
		w.WriteHeader(404)
		return
	}

	// Retrieve URL of auth request
	resource := fmt.Sprintf("%s://%s",
		r.Header["X-Forwarded-Proto"][0],
		r.Header["X-Forwarded-Host"][0])

	resourceURI := fmt.Sprintf("%s%s", resource, r.Header["X-Forwarded-Uri"][0])

	if authenticated, ok := session.Values["authenticated"].(bool); !ok || !authenticated {
		loginURL := fmt.Sprintf("%s?redirect_url=%s", context.LoginURL, url.QueryEscape(resourceURI))

		log.WithField("resource", resource).Debug("Client is not authenticated; redirecting to login")

		w.Header().Add("location", loginURL)
		w.WriteHeader(302)
		return
	}

	log.Trace("User authenticated, time to authorize")

	if context.grants[resource] == nil {
		log.WithField("URL", resource).Warning("Unrecognized resource")
		context.fetchGrants(resource)
	}

	if context.grants[resource] != nil {
		for _, grant := range context.grants[resource] {
			if grant.Username == session.Values["username"] {
				log.Trace("Found grant for user; authorizing")
				w.WriteHeader(200)
				return
			}
		}
	}

	w.WriteHeader(404)
	return
}

// HandleLogin handles a login request and redirects the user afterwards
// if they were redirected here by the /auth route
func (context *HTTP) HandleLogin(w http.ResponseWriter, r *http.Request) {
	session, _ := context.store.Get(r, "letmein-session")

	if auth, ok := session.Values["authenticated"].(bool); ok && auth {
		log.Debug("Authenticated user visited login")
		w.Header().Add("location", "/profile")
		w.WriteHeader(302)
		return
	} else {
		if r.Method == "POST" {
			r.ParseForm()

			if session.Values["csrf-token"] != r.PostFormValue("csrftoken") {
				w.Header().Add("location", "")
				w.WriteHeader(302)
				return
			}

			if ok, user := context.authenticate(r.PostFormValue("username"), r.PostFormValue("password")); ok {
				session.Values["authenticated"] = true
				session.Values["username"] = user.Username
				session.Values["user_id"] = user.ID
				session.Save(r, w)

				if r.FormValue("redirect_url") != "" {
					w.Header().Add("location", r.FormValue("redirect_url"))
					w.WriteHeader(302)
					return
				}

				w.Header().Add("location", "/profile")
				log.Warn("Missing redirect_url for login request")
				w.WriteHeader(302)
				return
			}
		}
	}

	r.ParseForm()

	type LoginContext struct {
		RedirectURL string
		CSRFToken   string
	}

	authorizeName := r.FormValue("redirect_url")
	if len(authorizeName) >= 10 && authorizeName[:10] == "/authorize" {
		var clientID string
		for k, v := range r.URL.Query() {
			if k == "redirect_url" {
				// Parse the urlescaped string back to an URL query
				// so we can extract query variables from it
				if u, err := url.Parse(v[0]); err == nil {
					for k, v := range u.Query() {
						if k == "client_id" {
							clientID = v[0]
							break
						}
					}
				}
			}
		}
		if clientID != "" {
			client, err := auth.OAuthClient{}.Get(clientID)
			if err != nil {
				log.Warning("Failed to fetch client during login")
			} else {
				authorizeName = client.Name
			}
		}
	}

	loginContext := LoginContext{
		RedirectURL: authorizeName,
		CSRFToken:   auth.CreateCSRFToken(),
	}

	session.Values["csrf-token"] = loginContext.CSRFToken
	session.Save(r, w)

	w.WriteHeader(200)
	context.loginHTMLTemplate.Execute(w, loginContext)
}

// HandleProfile shows a user profile page, displaying current grants
func (context *HTTP) HandleProfile(w http.ResponseWriter, r *http.Request) {
	session, _ := context.store.Get(r, "letmein-session")

	if authenticated, ok := session.Values["authenticated"].(bool); ok && authenticated {
		type ProfileContext struct {
			CSRFToken string
			Username  string
			URLs      []string
			Clients   []*auth.OAuthClient
		}

		grantedURLs := make([]string, 0)
		for _, claims := range context.grants {
			for _, claim := range claims {
				if claim.Username == session.Values["username"] {
					grantedURLs = append(grantedURLs, claim.URL)
				}
			}
		}

		userID, ok := session.Values["user_id"].(int64)
		if !ok {
			log.Error("Failed to cast user_id to int64")
			w.WriteHeader(500)
			return
		}

		var authorizedClients []*auth.OAuthClient
		authorizations, err := auth.OAuth2Authorization{UserID: userID}.All()
		if err != nil {
			log.WithError(err).Error("Failed to fetch user authorizations")
		} else {

			authorizedClients = make([]*auth.OAuthClient, len(authorizations))
			for i, authorization := range authorizations {
				client, err := auth.OAuthClient{}.Get(authorization.ClientID)
				if err != nil {
					log.WithError(err).WithField("client_id", authorization.ClientID).Error("Failed to fetch client")
					continue
				}
				authorizedClients[i] = client
			}
		}

		profileContext := ProfileContext{
			CSRFToken: auth.CreateCSRFToken(),
			Username:  session.Values["username"].(string),
			URLs:      grantedURLs,
			Clients:   authorizedClients,
		}

		session.Values["csrf-token"] = profileContext.CSRFToken
		session.Save(r, w)

		w.WriteHeader(200)
		context.profileHTMLTemplate.Execute(w, profileContext)
		return
	}
	w.WriteHeader(401)
}
func (context *HTTP) HandleProfileClient(w http.ResponseWriter, r *http.Request) {
	session, _ := context.store.Get(r, "letmein-session")

	if authenticated, ok := session.Values["authenticated"].(bool); !authenticated || !ok {
		w.WriteHeader(401)
		return
	}
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}
	if err := r.ParseForm(); err != nil {
		log.WithError(err).Error("Failed to parse form during client unauthorize")
		w.WriteHeader(500)
		return
	}
	clientID := r.Form["client_id"][0]
	userID := session.Values["user_id"].(int64)
	deleted, err := auth.OAuth2Authorization{}.Delete(clientID, userID)
	if !deleted || err != nil {
		log.WithError(err).Error("Failed to delete user authorization")
	}

	w.Header().Set("location", "/profile")
	w.WriteHeader(302)
}

func (context *HTTP) authenticate(username, password string) (bool, *auth.User) {
	return context.authDB.AuthenticateUser(username, password)
}

// HandleLogout deletes the session and effectively logs the user out
func (context *HTTP) HandleLogout(w http.ResponseWriter, r *http.Request) {

	// Delete ? 🤔
	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}

	session, err := context.store.Get(r, "letmein-session")

	if err != nil {
		log.Debug("Tried to delete non-existing session")
		w.WriteHeader(200)
		context.loginHTMLTemplate.Execute(w, nil)
		return
	}

	r.ParseForm()

	if session.Values["csrf-token"] != r.FormValue("csrftoken") {
		log.WithField("session-csrf", session.Values["csrf-token"]).WithField("request-csrf", r.PostFormValue("csrftoken")).Error("Failed csrf on logout")
		w.WriteHeader(400)
		return
	}

	session.Options.MaxAge = -1
	session.Save(r, w)

	w.Header().Add("location", "/login")
	w.WriteHeader(302)
	return
}

func (context *HTTP) fetchGrants(forceResource string) error {
	log.Debug("Fetching context.grants")
	grants := make(map[string][]*auth.Claim)
	claims, err := context.authDB.FetchClaims()

	if err != nil {
		log.WithError(err).Error("Failed to initialize context.grants")
		return err
	}

	for _, grant := range claims {
		if grants[grant.URL] == nil {
			grants[grant.URL] = make([]*auth.Claim, 0)
		}
		grants[grant.URL] = append(grants[grant.URL], grant)
	}

	if forceResource != "" && grants[forceResource] == nil {
		log.WithField("resource", forceResource).Warn("Forcing initialization of resource")
		grants[forceResource] = make([]*auth.Claim, 0)
	}

	context.grants = grants
	log.Debugf("Initialized context.grants with %d claims for %d URLs", len(claims), len(context.grants))
	return nil
}
