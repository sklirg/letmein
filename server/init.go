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

	// Get URL to login view
	loginURL := os.Getenv("LMI_LOGIN_URL")
	if loginURL == "" {
		loginURL = "http://localhost:8001"
		log.WithField("URL", context.LoginURL).Warn("Missing LMI_LOGIN_URL, setting it to default")
	}
	context.LoginURL = loginURL

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

	// CreateAuthDB()
	adb, err := auth.CreateContext()
	if err != nil {
		log.WithError(err).Fatal("Failed to init DB")
	}

	context.store = sessions.NewCookieStore([]byte(key))
	context.CookieName = cookieName
	context.loginHTMLTemplate = htmlTemplate
	context.adminHTMLTemplate = adminHTMLTemplate
	context.authDB = adb
}
