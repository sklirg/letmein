package server

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	oidc "github.com/coreos/go-oidc"
	oauth2_server "github.com/go-oauth2/oauth2/v4/server"
	log "github.com/sirupsen/logrus"
	jose "gopkg.in/square/go-jose.v2"

	"github.com/sklirg/letmein/auth"
)

type OpenID struct {
	host           string
	signkeyPublic  crypto.PublicKey
	signkeyPrivate crypto.PrivateKey
	JWK            *jose.JSONWebKey
	oauth2srv      *oauth2_server.Server
	authDB         *auth.Context
}

// Init initializes the OpenID module
func (oid *OpenID) Init(oauth2 *OAuth2) error {
	log.Info("hi from openid")

	db, err := auth.CreateContext()
	if err != nil {
		log.WithError(err).Error("Failed to create db context in oauth2")
	}
	host := os.Getenv("LMI_ROOT_URL")
	if host == "" {
		host = "http://localhost:8003"
		log.WithField("url", host).Warnf("Missing LMI_ROOT_URL, using '%s'", host)
	}
	oid.host = host
	oid.authDB = db
	oid.oauth2srv = oauth2.srv

	return nil
}

// discovery contains the required fields for an OpenID discovery response
type discovery struct {
	Issuer        string   `json:"issuer"`
	Auth          string   `json:"authorization_endpoint"`
	Token         string   `json:"token_endpoint"`
	Keys          string   `json:"jwks_uri"`
	UserInfo      string   `json:"userinfo_endpoint"`
	GrantTypes    []string `json:"grant_types_supported"`
	ResponseTypes []string `json:"response_types_supported"`
	Subjects      []string `json:"subject_types_supported"`
	IDTokenAlgs   []string `json:"id_token_signing_alg_values_supported"`
	Scopes        []string `json:"scopes_supported"`
	AuthMethods   []string `json:"token_endpoint_auth_methods_supported"`
	Claims        []string `json:"claims_supported"`
}

// HandleOpenIDDiscovery handles requests for the OID discovery endpoint
func (oid *OpenID) HandleOpenIDDiscovery(w http.ResponseWriter, r *http.Request) {
	d := discovery{
		Issuer:   oid.host,
		Auth:     fmt.Sprintf("%s/authorize", oid.host),
		Token:    fmt.Sprintf("%s/openid/token", oid.host),
		Keys:     fmt.Sprintf("%s/openid/keys", oid.host),
		UserInfo: fmt.Sprintf("%s/userinfo", oid.host),
		//DeviceEndpoint: fmt.Sprintf("%s/device/code", host),
		Subjects:   []string{"public"},
		GrantTypes: []string{"code"},
		//GrantTypes:     []string{grantTypeAuthorizationCode, grantTypeRefreshToken, grantTypeDeviceCode},
		IDTokenAlgs: []string{string(jose.RS256)},
		//IDTokenAlgs:    []string{string(jose.RS256), string(jose.ES512)},
		Scopes:      []string{"openid", "email", "groups", "profile"},
		AuthMethods: []string{"client_secret_basic"},
		Claims: []string{
			"aud", "email", "email_verified", "exp",
			"iat", "iss", "name", "sub",
		},
	}
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		log.Error("Failed to marshal discovery json")
		w.WriteHeader(500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// HandleOpenIDKeys handles requests for OID keys discovery
func (oid *OpenID) HandleOpenIDKeys(w http.ResponseWriter, r *http.Request) {
	jwks := jose.JSONWebKeySet{
		Keys: make([]jose.JSONWebKey, 0),
	}
	jwks.Keys = append(jwks.Keys, (*oid.JWK).Public())

	payload, err := json.MarshalIndent(jwks, "", "  ")
	if err != nil {
		log.WithError(err).Error("Failed to marshal signing key")
		w.WriteHeader(500)
		return
	}

	w.Header().Set("content-type", "application/json")
	w.Write(payload)
}

// OIDSubject is a Subject used in an OID Token request
type OIDSubject struct {
	ClientID string
	UserID   string
}

// OIDToken contains the fields in a JWT which is sent back
// to the user
type OIDToken struct {
	Issuer  string `json:"iss"`
	Subject string `json:"sub"`
	// Nonce
	Expiry   int64 `json:"exp"`
	IssuedAt int64 `json:"iat"`
}

// HandleOpenIDToken handles responding to a user with a signed JWT
func (oid *OpenID) HandleOpenIDToken(w http.ResponseWriter, r *http.Request) {
	// someone wants a  token, we should probably receive some credentials or sth here before
	// we willy nilly give out a token, but let's disregard that for now
	clientID := "000000"
	userID := "9"

	tokenLogger := log.WithFields(log.Fields{
		"client_id": clientID,
		"user_id":   userID,
	})

	tokenLogger.Trace("starting token request")

	sub := OIDSubject{
		ClientID: clientID,
		UserID:   userID,
	}

	tok := OIDToken{
		Issuer:   oid.host,
		Subject:  sub.UserID,
		Expiry:   time.Now().Add(time.Hour * 6).Unix(),
		IssuedAt: time.Now().Unix(),
	}

	tokenLogger.WithField("token", tok).Trace("Generated token")

	payload, err := json.Marshal(tok)
	if err != nil {
		log.WithError(err).Error("Failed to marshall token")
		w.WriteHeader(500)
		return
	}

	tokenLogger.Trace("Marshalled token")

	// sign into jwt

	// this creates new key every time pls no
	// sync once this instead lul
	if oid.signkeyPublic == nil {
		tokenLogger.Trace("Creating signing keys")
		//new_key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		new_key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.WithError(err).Error("Failed to create new signing key")
			w.WriteHeader(500)
			return
		}
		//oid.signkeyPublic = new_key.Public()
		//oid.signkeyPrivate = new_key
		oid.JWK = &jose.JSONWebKey{
			Key:   new_key,
			KeyID: "1",
			//Algorithm: "ES512",
			Algorithm: "RS256",
			Use:       "sig",
		}
		tokenLogger.Trace("Created signing keys")
	}

	tokenLogger.Trace("Starting signing process")
	//key := jose.SigningKey{Key: oid.signkeyPrivate, Algorithm: "ES512"}
	key := jose.SigningKey{Key: oid.JWK, Algorithm: "RS256"}
	signer, err := jose.NewSigner(key, &jose.SignerOptions{})
	if err != nil {
		log.WithError(err).Error("Failed to initialize signer")
		w.WriteHeader(500)
		return
	}
	tokenLogger.Trace("Signing token")
	sig, err := signer.Sign(payload)
	if err != nil {
		log.WithError(err).Error("Failed to sign payload")
		w.WriteHeader(500)
		return
	}
	jwt, err := sig.CompactSerialize()
	if err != nil {
		log.WithError(err).Error("Failed to compact sig")
		w.WriteHeader(500)
		return
	}
	tokenLogger.Trace("Returning signed token")
	//w.Header().Set("content-type", "application/json")
	w.Write([]byte(jwt))
}

type UserInfo struct {
	Subject           string `json:"sub"`
	Name              string `json:"name,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Email             string `json:"email,omitempty"`
	EmailVerified     bool   `json:"email_verified,omitempty"`
	Picture           string `json:"picture,omitempty"`
}

func (oid *OpenID) HandleUserInfo(w http.ResponseWriter, r *http.Request) {
	// once thing
	provider, err := oidc.NewProvider(r.Context(), oid.host)
	if err != nil {
		log.WithError(err).Error("Failed to auto-discover provider")
		w.WriteHeader(500)
		return
	}
	log.WithField("provider", oid.host).Info("Auto-discovered provider")

	// auth etc
	const bearer = "Bearer "
	authHeader := r.Header.Get("authorization")
	if len(authHeader) < len(bearer) || bearer != authHeader[:len(bearer)] {
		w.Header().Set("WWW-Authenticate", "Bearer")
		w.WriteHeader(401)
		return
	}

	token := authHeader[len(bearer):]

	//verifier := oidc.NewVerifier(oid.host, &storageKeySet{oid.srv.storage}, &oidc.Config{SkipClientIDCheck: true})
	verifier := provider.Verifier(&oidc.Config{SkipClientIDCheck: true, SkipIssuerCheck: true, SkipExpiryCheck: true})

	//log.Debugf("Provider %+v", provider)
	//log.Debugf("Verifier %#v", verifier)

	idToken, err := verifier.Verify(r.Context(), token)
	log.Warnf("IdToken %s", idToken)
	//log.Debugf("IDToken %#v", idToken)
	var userID string
	if err != nil {
		log.WithError(err).Debug("Failed to verify ID Token")

		log.Debug("Trying to extract and validate a OAuth2 token")
		oauth2_token, err := oid.oauth2srv.ValidationBearerToken(r)
		if err != nil {
			log.WithError(err).Debug("Failed to extract OAuth2 Token")
			w.WriteHeader(401)
			return
		} else {
			log.Trace("Found user with OAuth2 token")
			userID = oauth2_token.GetUserID()
		}
	} else {
		userID = idToken.Subject
	}

	dbUser, err := oid.authDB.FetchUser(userID)
	if err != nil {
		log.WithError(err).WithField("user_id", userID).Error("Failed to fetch user")
		w.WriteHeader(401)
		return
	}

	log.WithField("dbUser", dbUser).Trace("We have a valid token, either oauth2 or id")

	userinfo := UserInfo{
		Subject:       strconv.Itoa(int(dbUser.ID)),
		Name:          dbUser.Username,
		Email:         dbUser.Email,
		EmailVerified: dbUser.EmailVerified,
	}

	payload, err := json.Marshal(userinfo)
	if err != nil {
		log.WithError(err).Error("Failed to marshal userinfo")
		w.WriteHeader(500)
		return
	}

	w.Header().Set("content-type", "application/json")
	w.Write(payload)
}

func (oid *OpenID) HandleUserInfoEmails(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(400)
}
