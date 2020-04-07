package server

import (
	"net/http"

	log "github.com/sirupsen/logrus"

	"github.com/sklirg/letmein/auth"
)

// HandleAdmin renders the admin page
func (context *HTTP) HandleAdmin(w http.ResponseWriter, r *http.Request) {
	session, _ := context.store.Get(r, "letmein-session")
	// @todo csrf

	// Let's first check if user is authenticated and authorized
	if authed, ok := session.Values["admin"].(bool); ok && authed {
		users, err := context.authDB.FetchUsers()
		if err != nil {
			log.WithError(err).Error("Failed to fetch users")
			w.WriteHeader(500)
			return
		}
		sites, err := context.authDB.FetchSites()
		if err != nil {
			log.WithError(err).Error("Failed to fetch sites")
			w.WriteHeader(500)
			return
		}
		claims, err := context.authDB.FetchClaims()
		if err != nil {
			log.WithError(err).Error("Failed to fetch claims")
			w.WriteHeader(500)
			return
		}

		type adminTemplateContext struct {
			Users  []*auth.User
			Sites  []*auth.Site
			Claims []*auth.Claim
		}

		ctx := adminTemplateContext{
			Users:  users,
			Sites:  sites,
			Claims: claims,
		}

		if err := context.adminHTMLTemplate.Execute(w, ctx); err != nil {
			log.WithError(err).Error("Template render error")
		}
		return
	}

	// If the user isn't logged in and we receive a POST request, we assume
	// it's an authentication request. Try logging the user in.
	if r.Method == "POST" {
		r.ParseForm()

		if context.authenticateAdmin(r.PostFormValue("username"), r.PostFormValue("password")) {
			log.WithField("username", r.PostFormValue("username")).Info("Adminstrator logged in")
			session.Values["admin"] = true

			session.Save(r, w)

			w.Header().Add("location", "/admin")
			w.WriteHeader(302)
			return
		}
		log.WithField("username", r.PostFormValue("username")).Warning("Failed adminstrator login attempt")
	}

	// Let's reuse the login template for login because we basically do the same thing.
	w.WriteHeader(200)
	context.loginHTMLTemplate.Execute(w, nil)
}

func (context *HTTP) authenticateAdmin(username, password string) bool {
	return context.authDB.AuthenticateAdmin(username, password)
}

// HandleNewUser handles an incoming request for adding a new user
func (context *HTTP) HandleNewUser(w http.ResponseWriter, r *http.Request) {
	session, _ := context.store.Get(r, "letmein-session")

	if admin, ok := session.Values["admin"].(bool); !ok || !admin {
		status := 401
		if ok {
			status = 403
		}
		w.WriteHeader(status)
		return
	}

	if r.Method != "POST" {
		w.WriteHeader(405)
		return
	}

	r.ParseForm()

	username := r.PostFormValue("username")

	if username == "" || r.PostFormValue("password") == "" {
		w.WriteHeader(400)
		return
	}

	err := context.authDB.AddUser(username, r.PostFormValue("password"))
	if err != nil {
		log.WithError(err).WithField("username", username).Error("Failed to insert user")
		w.WriteHeader(400)
		return
	}

	log.WithField("username", username).Debug("Successfully inserted a new user")

	w.Header().Add("Location", "/admin")
	w.WriteHeader(302)
	return
}

// HandleNewSite handles an incoming request for adding a new site
func (context *HTTP) HandleNewSite(w http.ResponseWriter, r *http.Request) {
	session, _ := context.store.Get(r, "letmein-session")

	if admin, ok := session.Values["admin"].(bool); !ok || !admin {
		status := 401
		if ok {
			status = 403
		}
		w.WriteHeader(status)
		return
	}

	r.ParseForm()

	url := r.PostFormValue("url")

	if url == "" {
		w.WriteHeader(400)
		return
	}

	err := context.authDB.AddSite(url)
	if err != nil {
		log.WithError(err).WithField("url", url).Error("Failed to insert site")
		w.WriteHeader(400)
		return
	}

	log.WithField("url", url).Debug("Successfully inserted a new site")

	w.Header().Add("Location", "/admin")
	w.WriteHeader(302)
	return
}

// HandleNewClaim handles an incoming request for adding a new claim
func (context *HTTP) HandleNewClaim(w http.ResponseWriter, r *http.Request) {
	session, _ := context.store.Get(r, "letmein-session")

	if admin, ok := session.Values["admin"].(bool); !ok || !admin {
		status := 401
		if ok {
			status = 403
		}
		w.WriteHeader(status)
		return
	}

	r.ParseForm()

	username := r.PostFormValue("username")
	url := r.PostFormValue("url")

	if username == "" || url == "" {
		w.WriteHeader(400)
		return
	}

	err := context.authDB.AddClaim(username, url)
	if err != nil {
		log.WithFields(log.Fields{
			"error":    err,
			"username": username,
			"url":      url,
		}).Error("Failed to insert claim")
		w.WriteHeader(400)
		return
	}

	log.WithField("username", username).WithField("url", url).Debug("Successfully inserted a new claim")

	w.Header().Add("Location", "/admin")
	w.WriteHeader(302)
	return
}
