package server

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strconv"

	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/gorilla/sessions"
	log "github.com/sirupsen/logrus"

	"github.com/sklirg/letmein/auth"
)

// OAuth2 contains required clients for configuring and running
// OAuth2
type OAuth2 struct {
	srv               *server.Server // OAuth2 lib server
	manager           *manage.Manager
	authDB            *auth.Context
	store             *sessions.CookieStore
	authorizeTemplate *template.Template
}

// Init initializes the context for the OAuth2 module
func (oauth2 *OAuth2) Init(httpContext *HTTP) {
	log.Info("hi from oauth2")
	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)

	manager.MustTokenStorage(store.NewMemoryTokenStore())

	oauth2.manager = manager
	oauth2.UpdateClientStore()

	srv := server.NewDefaultServer(manager)
	srv.SetAllowGetAccessRequest(true)
	srv.SetClientInfoHandler(server.ClientFormHandler)
	srv.SetUserAuthorizationHandler(oauth2.userAuthorizeHandler)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.WithError(err).Error("OAuth2 error")
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.WithField("resp err", re.Error).Debug("Response error")
	})

	oauth2.authorizeTemplate = httpContext.authorizeHTMLTemplate

	db, err := auth.CreateContext()
	if err != nil {
		log.WithError(err).Error("Failed to create db context in oauth2")
	}

	// Need the same session store as in public endpoints..
	// @ToDo: do in a nicer way
	oauth2.store = httpContext.store

	oauth2.srv = srv
	oauth2.authDB = db
}

// HandleAuthorize is the handlerfunc for the oauth2 /authorize route
func (oauth2 *OAuth2) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	logger := log.WithField("foo", "bar")
	logger.Trace("incoming auth request")
	session, err := oauth2.store.Get(r, "letmein-session")

	var userID int64

	userID, ok := session.Values["user_id"].(int64)
	if !ok {
		logger.Error("Failed to cast user_id to int64")
	}

	var clientID string
	for k, v := range r.URL.Query() {
		if k == "client_id" {
			clientID = v[0]
			break
		}
	}

	// See if this has been authorized before
	if clientID != "" && userID != 0 {
		logger = logger.WithFields(log.Fields{
			"client_id": clientID,
			"user_id":   userID,
		})
		authorization, err := auth.OAuth2Authorization{}.Get(clientID, userID)
		if err != nil {
			logger.WithError(err).Warning("Failed to get previous OAuth2 authorization")
		}
		if authorization != nil {
			logger.Debug("Found existing authorization")

			// Copy pasta from end of func
			if err := oauth2.srv.HandleAuthorizeRequest(w, r); err != nil {
				logger.WithError(err).Error("HandleAuthorize failed")
				http.Error(w, err.Error(), http.StatusBadRequest)
			}
			return
		} else {
			logger.Trace("Could not find an existing authorization for user/client")
		}
	}

	if err != nil {
		logger.WithError(err).Error("Failed to get session")
		w.WriteHeader(500)
		return
	}
	if authenticated, ok := session.Values["authenticated"].(bool); !authenticated || !ok {
		logger.WithField("url", r.URL).Debug("Redirecting to login")

		w.Header().Set("location", fmt.Sprintf("/login?redirect_url=%s", url.QueryEscape(r.URL.String())))
		w.WriteHeader(http.StatusFound)
		return
	}
	if r.Method == "GET" {
		type Grant struct {
			Name        string
			Description string
			Authorize   bool
			Optional    bool
		}
		type AuthorizeContext struct {
			CSRFToken string
			Client    *auth.OAuthClient
			Grants    []Grant
			//Claims    []Grant // OID name of grants, keep both? separate? combine?
			Authorize bool
		}
		client, err := auth.OAuthClient{}.Get(clientID)
		if err != nil {
			log.WithError(err).Error("Failed to fetch client during authorize grant")
			w.WriteHeader(500)
			return
		}
		grants := make([]Grant, len(client.Grants))
		for i, grant := range client.Grants {
			grants[i] = Grant{
				Name:        grant.Name,
				Description: grant.Description,
				Optional:    grant.Optional,
				Authorize:   !grant.Optional, // Auto-authorize all non-optional grants
			}
		}

		authorizeContext := AuthorizeContext{
			CSRFToken: auth.CreateCSRFToken(),
			Client:    client,
			Grants:    grants,
		}

		session.Values["csrf-token"] = authorizeContext.CSRFToken
		session.Save(r, w)

		w.WriteHeader(200)
		oauth2.authorizeTemplate.Execute(w, authorizeContext)
		return
	} else if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			logger.WithError(err).Error("Failed to parse authorization form")
			w.WriteHeader(400)
			return
		}
		logger.Debug("Received POST")
		logger.Debugf("Form: %#v", r.Form)
		if session.Values["csrf-token"] != r.PostFormValue("csrftoken") {
			logger.Debug("Failed CSRF check")
			w.WriteHeader(400)
			return
		}
		if r.PostFormValue("cancel-request") == "cancel" {
			// Abort authorization
			w.Header().Set("location", "/profile")
			w.WriteHeader(302)
			return
		}
	} else {
		w.WriteHeader(405)
		return
	}

	logger.Trace("Authorize ack")

	// Make sure we have all known clients in state
	if err := oauth2.UpdateClientStore(); err != nil {
		logger.WithError(err).Warning("Failed to update OAuth2 Client store")
	}

	// Fetch Client just so we know its values
	client, err := auth.OAuthClient{}.Get(clientID)
	if err != nil {
		logger.WithError(err).Error("Failed to fetch client")
		w.WriteHeader(500)
		return
	} else if client == nil {
		logger.Warn("Client fetch resulted in nil client")
		w.WriteHeader(404)
		return
	}

	grants := make([]auth.OAuthGrant, 0)
	for k, v := range r.Form {
		// Find form fields for grants,
		// match them with the grants
		// listed in the database,
		// and apply those grants.
		if len(k) > 6 && k[:6] == "grant-" {
			for _, clientGrant := range client.Grants {
				if clientGrant.Name == v[0] {
					grants = append(grants, clientGrant)
				}
			}
		}
	}

	// Store information about client grant
	authorization := auth.OAuth2Authorization{
		ClientID: client.ClientID,
		UserID:   userID,
		Grants:   grants,
	}
	if _, err := authorization.Save(); err != nil {
		log.WithError(err).Error("Failed to persist authorization to database")
		w.WriteHeader(500)
		return
	}

	if err := oauth2.srv.HandleAuthorizeRequest(w, r); err != nil {
		logger.WithError(err).Error("HandleAuthorize failed")
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

// HandleToken is the http handlerfunc for the oauth2 /token endpoint
func (oauth2 *OAuth2) HandleToken(w http.ResponseWriter, r *http.Request) {
	log.WithField("r", r).Debug("incoming token request")
	oauth2.srv.HandleTokenRequest(w, r)
}

// userAuthorizeHandler contains the logic for fetching the
// userID for the authorizing user. It is called upon by
// HandleAuthorize after it has authorized a user.
func (oauth2 *OAuth2) userAuthorizeHandler(w http.ResponseWriter, r *http.Request) (userID string, err error) {
	session, err := oauth2.store.Get(r, "letmein-session")
	if err != nil {
		log.WithError(err).Error("Failed getting session")
		w.WriteHeader(500)
		return
	}

	// This is duplicated I think,
	// already checked in HandleAuthorize
	authed, ok := session.Values["authenticated"].(bool)
	if !ok || !authed {
		log.Trace("Redirecting to login during /authorize request")

		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
		return
	}

	log.Debug("Everything looks good for /authorize")

	uID := session.Values["user_id"].(int64)
	userID = strconv.Itoa(int(uID))
	log.Tracef("Hello, %s", userID)

	return userID, nil
}

func (oauth2 *OAuth2) UpdateClientStore() error {
	clients, err := auth.OAuthClient{}.All()
	if err != nil {
		log.WithError(err).Error("Failed to fetch clients during client store update")
		return err
	}

	clientStore := store.NewClientStore()
	for _, client := range clients {
		clientStore.Set(client.ClientID, &models.Client{
			ID:     client.ClientID,
			Secret: client.ClientSecret,
			Domain: client.RedirectURIs[0], // the rest should be checked manually in /authorize
			UserID: strconv.Itoa(int(client.UserID)),
		})
	}
	oauth2.manager.MapClientStorage(clientStore)
	log.WithField("num_clients", len(clients)).Info("Updated OAuth2 Client Store")
	return nil
}
