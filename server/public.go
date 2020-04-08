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
	store             *sessions.CookieStore
	CookieName        string
	CookieDomain      string
	LoginURL          string
	loginHTMLTemplate *template.Template
	adminHTMLTemplate *template.Template
	authDB            *auth.Context
	grants            map[string][]*auth.Claim
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

	// @ToDo: Do this in an init-style method, e.g. using sync.DoOnce
	if context.grants == nil {
		log.Debug("Initializing context.grants")
		context.grants = make(map[string][]*auth.Claim)
		claims, err := context.authDB.FetchClaims()

		if err != nil {
			log.WithError(err).Error("Failed to initialize context.grants")
			w.WriteHeader(500)
			return
		}

		for _, grant := range claims {
			if context.grants[grant.URL] == nil {
				context.grants[grant.URL] = make([]*auth.Claim, 0)
			}
			context.grants[grant.URL] = append(context.grants[grant.URL], grant)
		}

		log.Debugf("Initialized context.grants with %d claims for %d URLs", len(claims), len(context.grants))
	}

	if context.grants[resource] != nil {
		for _, grant := range context.grants[resource] {
			if grant.Username == session.Values["username"] {
				log.Trace("Found grant for user; authorizing")
				w.WriteHeader(200)
				return
			}
		}
	} else {
		log.WithField("URL", resource).Warning("Unrecognized resource")
		w.WriteHeader(404)
		return
	}

	log.Error("Not sure how we got here but hey let's go")
	w.WriteHeader(500)
	return
}

// HandleLogin handles a login request and redirects the user afterwards
// if they were redirected here by the /auth route
func (context *HTTP) HandleLogin(w http.ResponseWriter, r *http.Request) {
	session, _ := context.store.Get(r, "letmein-session")
	// @todo csrf

	if auth, ok := session.Values["authenticated"].(bool); ok && auth {
		log.Debug("Authenticated user visited login")
	} else {
		if r.Method == "POST" {
			r.ParseForm()

			if context.authenticate(r.PostFormValue("username"), r.PostFormValue("password")) {
				session.Values["authenticated"] = true
				session.Values["username"] = r.PostFormValue("username")
				session.Save(r, w)

				if r.FormValue("redirect_url") != "" {
					w.Header().Add("location", r.FormValue("redirect_url"))
					w.WriteHeader(302)
					return
				}

				// Login OK but no redirect URL, just give 200 I guess
				log.Warn("Missing redirect_url for login request")
				w.WriteHeader(200)
				return
			}
		}
	}

	r.ParseForm()

	type LoginContext struct {
		RedirectURL string
	}

	loginContext := LoginContext{
		RedirectURL: r.FormValue("redirect_url"),
	}

	w.WriteHeader(200)
	context.loginHTMLTemplate.Execute(w, loginContext)
}

func (context *HTTP) authenticate(username, password string) bool {
	return context.authDB.AuthenticateUser(username, password)
}

// HandleLogout deletes the session and effectively logs the user out
func (context *HTTP) HandleLogout(w http.ResponseWriter, r *http.Request) {
	session, err := context.store.Get(r, "letmein-session")

	if err != nil {
		log.Debug("Tried to delete non-existing session")
		w.WriteHeader(400)
		context.loginHTMLTemplate.Execute(w, nil)
		return
	}

	session.Options.MaxAge = -1
	session.Save(r, w)

	w.WriteHeader(200)
	context.loginHTMLTemplate.Execute(w, nil)
	return
}
