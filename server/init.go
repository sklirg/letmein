package server

import (
	"fmt"
	"html/template"
	"io/ioutil"
	"os"

	"github.com/gorilla/sessions"
	log "github.com/sirupsen/logrus"

	"github.com/sklirg/letmein/auth"
)

// Init initializes the HTTP struct for use internally
func (context *HTTP) Init() {
	// Get store key
	key := os.Getenv("LMI_KEY")

	if key == "" {
		log.Fatal("A key for the session store needs to be defined. 16, 24 or 32 bytes long.")
	}

	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		log.WithField("length", len(key)).Fatal("The key for the session store needs to exactly 16, 24 or 32 bytes long.")
	}

	// Check if we should set a custom name for the cookie
	cookieName := os.Getenv("LMI_COOKIE_NAME")
	if cookieName == "" {
		cookieName = "letmein"
	}

	// Set custom domain for the cookie if set
	context.CookieDomain = os.Getenv("LMI_COOKIE_DOMAIN")

	// Get URL to login view
	loginURL := os.Getenv("LMI_LOGIN_URL")
	if loginURL == "" {
		loginURL = "http://localhost:8001/login"
		log.WithField("URL", context.LoginURL).Warn("Missing LMI_LOGIN_URL, setting it to default")
	}
	context.LoginURL = loginURL
	log.WithField("login_url", context.LoginURL).Debug("Login URL configured")

	templateDir := os.Getenv("LMI_TEMPLATE_DIR")
	if templateDir == "" {
		templateDir = "./server/templates"
	}

	// Read HTML template from file
	templateFilePath := fmt.Sprintf("%s/index.html", templateDir)
	templateContents, err := ioutil.ReadFile(templateFilePath)
	if err != nil {
		log.WithError(err).Fatal("Failed to read template file")
	}
	htmlTemplate := template.New("login")
	htmlTemplate.Parse(string(templateContents))

	// admin template
	adminTemplateFilePath := fmt.Sprintf("%s/admin.html", templateDir)
	adminTemplateContents, err := ioutil.ReadFile(adminTemplateFilePath)
	if err != nil {
		log.WithError(err).Fatal("Failed to read template file")
	}

	adminHTMLTemplate := template.New("admin")
	adminHTMLTemplate.Parse(string(adminTemplateContents))

	// profile template
	profileFilePath := fmt.Sprintf("%s/profile.html", templateDir)
	profileContents, err := ioutil.ReadFile(profileFilePath)
	if err != nil {
		log.WithError(err).Fatal("Failed to read template file")
	}

	profileHTMLTemplate := template.New("profile")
	profileHTMLTemplate.Parse(string(profileContents))

	// authorize template
	authorizeFilePath := fmt.Sprintf("%s/authorize.html", templateDir)
	authorizeContents, err := ioutil.ReadFile(authorizeFilePath)
	if err != nil {
		log.WithError(err).Fatal("Failed to read template file")
	}

	authorizeHTMLTemplate := template.New("authorize")
	authorizeHTMLTemplate.Parse(string(authorizeContents))
	context.authorizeHTMLTemplate = authorizeHTMLTemplate

	// CreateAuthDB()
	adb, err := auth.CreateContext()
	if err != nil {
		log.WithError(err).Fatal("Failed to init DB")
	}

	// Initialize session store
	store := sessions.NewCookieStore([]byte(key))

	// Set custom domain for cookies if set
	if context.CookieDomain != "" {
		storeOptions := store.Options
		storeOptions.Domain = context.CookieDomain
		store.Options = storeOptions
	}

	context.store = store
	context.store.Options.Domain = context.CookieDomain
	context.CookieName = cookieName
	context.loginHTMLTemplate = htmlTemplate
	context.adminHTMLTemplate = adminHTMLTemplate
	context.profileHTMLTemplate = profileHTMLTemplate
	context.authDB = adb

	if err := context.fetchGrants(""); err != nil {
		log.WithError(err).Fatal("failed to fetch grants")
	}
}
