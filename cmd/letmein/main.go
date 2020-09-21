package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/sklirg/letmein/server"
)

func main() {

	// @ToDo: Set this some smarter way
	log.SetLevel(log.TraceLevel)

	host := os.Getenv("HOST")
	if host == "" {
		host = "[::1]"
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8003"
	}

	router := http.Server{}
	router.Addr = fmt.Sprintf("%s:%s", host, port)

	h := server.HTTP{}
	h.Init()

	// Redirect / to /login cause nothing happens at /login
	// Tbh nothing happens at /login either but it looks better

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Lol this redirects favicon too gg
		// w.Header().Add("location", "/login")
		// w.WriteHeader(302)
		w.Write([]byte("<html><script>window.location=\"/login\"</script></html>"))
	})

	// CSS
	staticDir := os.Getenv("LMI_STATIC")
	if staticDir == "" {
		staticDir = "./server/static"
	}
	css, err := ioutil.ReadFile(fmt.Sprintf("%s/css/styles.css", staticDir))
	cssBytes := []byte(css)

	if err != nil {
		log.WithError(err).Fatal("Failed to read CSS file!")
	}
	http.HandleFunc("/static/css/styles.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("content-type", "text/css")
		w.WriteHeader(200)
		w.Write(cssBytes)
	})

	// Init OAuth2
	oauth2 := server.OAuth2{}
	oauth2.Init(&h)

	// Init OpenID
	oid := server.OpenID{}
	oid.Init(&oauth2)

	http.HandleFunc("/auth", h.HandleAuth)
	http.HandleFunc("/login", h.HandleLogin)
	http.HandleFunc("/logout", h.HandleLogout)
	http.HandleFunc("/profile", h.HandleProfile)
	http.HandleFunc("/profile/client", h.HandleProfileClient)

	// Admin sites
	http.HandleFunc("/admin", h.HandleAdmin)
	http.HandleFunc("/admin/user", h.HandleNewUser)
	http.HandleFunc("/admin/site", h.HandleNewSite)
	http.HandleFunc("/admin/claim", h.HandleNewClaim)
	http.HandleFunc("/admin/client", h.HandleNewClient)

	// OAuth2 routes
	http.HandleFunc("/authorize", oauth2.HandleAuthorize)
	http.HandleFunc("/token", oauth2.HandleToken)

	// OpenID routes
	http.HandleFunc("/.well-known/openid-configuration", oid.HandleOpenIDDiscovery)
	http.HandleFunc("/openid/token", oid.HandleOpenIDToken)
	http.HandleFunc("/openid/keys", oid.HandleOpenIDKeys)
	http.HandleFunc("/userinfo", oid.HandleUserInfo)
	http.HandleFunc("/userinfo/emails", oid.HandleUserInfoEmails)

	log.Infof("Listening on %s", router.Addr)

	fmt.Println(router.ListenAndServe())
}
