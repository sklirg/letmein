package main

import (
	"fmt"
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

	http.HandleFunc("/auth", h.HandleAuth)
	http.HandleFunc("/login", h.HandleLogin)
	http.HandleFunc("/logout", h.HandleLogout)
	http.HandleFunc("/profile", h.HandleProfile)

	// Admin sites
	http.HandleFunc("/admin", h.HandleAdmin)
	http.HandleFunc("/admin/user", h.HandleNewUser)
	http.HandleFunc("/admin/site", h.HandleNewSite)
	http.HandleFunc("/admin/claim", h.HandleNewClaim)

	log.Infof("Listening on %s", router.Addr)

	fmt.Println(router.ListenAndServe())
}
