package auth

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	// Imported for side effects
	_ "github.com/lib/pq"
	log "github.com/sirupsen/logrus"
)

type redirectURIs []string

// OAuthClient contains client grant information
// for a OAuth2 or OpenID client-to-user authorization.
type OAuthClient struct {
	UserID       int64
	Name         string
	ClientID     string
	ClientSecret string
	AuthorizedAt time.Time // this is created at really
	RedirectURIs redirectURIs
	Grants       oAuthGrants
}

type OAuthGrant struct {
	Name        string
	Description string
	Optional    bool // If the grant is optional or required
}
type oAuthGrants []OAuthGrant

type OAuth2Authorization struct {
	UserID       int64
	ClientID     string
	AuthorizedAt time.Time
	Grants       oAuthGrants
}

func (client OAuthClient) Get(clientID string) (*OAuthClient, error) {
	rows, err := db.Query("SELECT client_id, client_secret, name, grants, redirect_uris from oauth_clients")
	defer rows.Close()

	if err != nil {
		log.WithError(err).Error("SELECT clients failed")
		return nil, err
	}

	clients := make([]*OAuthClient, 0)
	for rows.Next() {
		var clientID string
		var clientSecret string
		var name string
		var grants sql.NullString
		var redirectURIs string
		if err := rows.Scan(&clientID, &clientSecret, &name, &grants, &redirectURIs); err != nil {
			log.WithError(err).Error("Clients row iteration failed")
			break
		}
		var oauthGrants oAuthGrants
		if grants.Valid {
			oauthGrants = oauthGrants.Parse(grants.String)
		}
		clients = append(clients, &OAuthClient{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Name:         name,
			Grants:       oauthGrants,
			RedirectURIs: strings.Split(redirectURIs, "\n"),
		})

	}

	return clients[0], nil
}

// Save stores a new OAuthClient in the database
func (client OAuthClient) Save() (*OAuthClient, error) {
	log.WithField("name", client.Name).Info("Inserting new OAuth Client")
	// if client.ID check
	clientId, err := uuid.NewRandom()
	if err != nil {
		log.WithError(err).Error("Failed to generate random client id")
		return nil, err
	}

	clientSecret, err := uuid.NewRandom()
	if err != nil {
		log.WithError(err).Error("Failed to generate random client secret")
		return nil, err
	}

	redirectURIs := strings.Join(client.RedirectURIs, "\n")

	grants := sql.NullString{
		String: client.Grants.String(),
		Valid:  len(client.Grants.String()) > 0,
	}

	_, err = db.Query("INSERT INTO oauth_clients (client_id, client_secret, redirect_uris, created_at, user_id, grants, name) VALUES ($1, $2, $3, $4, $5, $6, $7)", clientId.String(), clientSecret.String(), redirectURIs, time.Now(), client.UserID, grants, client.Name)

	if err != nil {
		log.WithError(err).Error("Failed to insert OAuthClient")
		return nil, err
	}

	return &OAuthClient{
		ClientID:     clientId.String(),
		ClientSecret: clientSecret.String(),
		RedirectURIs: client.RedirectURIs,
	}, nil
}

func (client OAuthClient) All() ([]*OAuthClient, error) {
	rows, err := db.Query("SELECT client_id, client_secret, name, grants, redirect_uris from oauth_clients")
	defer rows.Close()

	if err != nil {
		log.WithError(err).Error("SELECT clients failed")
		return nil, err
	}

	clients := make([]*OAuthClient, 0)
	for rows.Next() {
		var clientID string
		var clientSecret string
		var name string
		var grants sql.NullString
		var redirectURIs string
		if err := rows.Scan(&clientID, &clientSecret, &name, &grants, &redirectURIs); err != nil {
			log.WithError(err).Error("Clients row iteration failed")
			break
		}
		var oauthGrants oAuthGrants
		if grants.Valid {
			oauthGrants = oauthGrants.Parse(grants.String)
		}
		clients = append(clients, &OAuthClient{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Name:         name,
			Grants:       oauthGrants,
			RedirectURIs: strings.Split(redirectURIs, "\n"),
		})

	}

	return clients, nil
}

func (client OAuthClient) Delete(id string) (bool, error) {
	log.WithField("id", id).Info("Deleting client")
	_, err := db.Query("DELETE FROM oauth_clients WHERE client_id = $1", id)
	if err != nil {
		log.WithError(err).Error("Failed to delete client")
		return false, err
	}

	return true, nil
}

func (authorization OAuth2Authorization) Save() (*OAuth2Authorization, error) {
	logger := log.WithFields(log.Fields{
		"client_id": authorization.ClientID,
		"user_id":   authorization.UserID,
	})
	logger.Info("Inserting OAuth2 Authorization")

	_, err := db.Query("INSERT INTO oauth_client_authorization (client_id, user_id, authorized_at, grants) VALUES($1, $2, $3, $4)", authorization.ClientID, authorization.UserID, time.Now(), authorization.Grants.String())
	if err != nil {
		log.WithError(err).Error("Failed to authorize client for user")
		return nil, err
	}

	logger.Debug("Inserted OAuth2 Authorization")

	return nil, nil
}

func (authorization OAuth2Authorization) Get(clientID string, userID int64) (*OAuth2Authorization, error) {
	rows, err := db.Query("SELECT client_id, user_id, authorized_at, grants FROM oauth_client_authorization WHERE client_id = $1 AND user_id = $2", clientID, userID)
	if err != nil {
		log.WithError(err).Error("Failed to get oauth2 authorization")
		return nil, err
	}

	for rows.Next() {
		var grants sql.NullString
		if err := rows.Scan(&authorization.ClientID, &authorization.UserID, &authorization.AuthorizedAt, &grants); err != nil {
			log.WithError(err).Error("Failed to scan oauth2 authorization row")
			return nil, err
		} else {
			if grants.Valid {
				authorization.Grants = oAuthGrants{}.Parse(grants.String)
			}
		}
		return &authorization, nil
	}
	return nil, nil
}

// All only lists all for the current user.
func (authorization OAuth2Authorization) All() ([]*OAuth2Authorization, error) {
	if authorization.UserID == 0 {
		err := errors.New("All() for OAuth2Authorization requires UserID set")
		log.WithError(err).Error()
		return nil, err
	}
	rows, err := db.Query("SELECT client_id, user_id, authorized_at, grants FROM oauth_client_authorization WHERE user_id = $1", authorization.UserID)
	if err != nil {
		log.WithError(err).Error("Failed to get oauth2 authorizations")
		return nil, err
	}

	authorizations := make([]*OAuth2Authorization, 0)
	for rows.Next() {
		aut := OAuth2Authorization{}
		var grants sql.NullString
		if err := rows.Scan(&aut.ClientID, &aut.UserID, &aut.AuthorizedAt, &grants); err != nil {
			log.WithError(err).Error("Failed to scan oauth2 authorization row")
			return nil, err
		} else {
			if grants.Valid {
				aut.Grants = oAuthGrants{}.Parse(grants.String)
			}
		}
		authorizations = append(authorizations, &aut)
	}
	return authorizations, nil
}

func (authorization OAuth2Authorization) Delete(clientID string, userID int64) (bool, error) {
	logger := log.WithFields(log.Fields{
		"client_id": clientID,
		"user_id":   userID,
	})
	logger.Info("Deleting client authorization")
	_, err := db.Query("DELETE FROM oauth_client_authorization WHERE user_id = $1 AND client_id = $2", userID, clientID)
	if err != nil {
		log.WithError(err).Error("Failed to delete client authorization")
		return false, err
	}
	logger.Debug("Deleted client authorization")
	return true, nil
}

func (grants oAuthGrants) String() string {
	grantStrings := make([]string, len(grants))
	for i, grant := range grants {
		grantStrings[i] = grant.Name
	}
	return strings.Join(grantStrings, ",")
}

func (grants oAuthGrants) Parse(s string) oAuthGrants {
	oauthGrants := make(oAuthGrants, len(strings.Split(s, ",")))
	for i, grant := range strings.Split(s, ",") {
		oauthGrants[i] = OAuthGrant{
			Name: grant,
		}
	}
	return oauthGrants
}
