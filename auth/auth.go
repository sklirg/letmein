package auth

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"os"

	"github.com/google/uuid"
	// Imported for side effects
	_ "github.com/lib/pq"
	log "github.com/sirupsen/logrus"
)

// Context contains the database connection for the auth package
type Context struct {
	db *sql.DB
}

// User contains the fields of the User type
type User struct {
	ID       int64
	Username string
}

// Site contains the fields of the Site type
type Site struct {
	ID  int64
	URL string
}

// Claim contains the fields of the Claim type
type Claim struct {
	Username string
	URL      string
}

// CreateContext initializes the database
func CreateContext() (*Context, error) {
	connStr := os.Getenv("DATABASE_URL")

	if connStr == "" {
		log.Info("Missing database string. Example: 'postgres://pqgotest:password@localhost/pqgotest?sslmode=verify-full'")
		log.Fatal("Database string for postgresql is required. Exiting.")
	}

	// connStr := "user=lmi dbname=lmi sslmode=disable"
	// connStr := "user=lmi dbname=lmi sslmode=verify-full"
	// connStr := "postgres://pqgotest:password@localhost/pqgotest?sslmode=verify-full"
	db, err := sql.Open("postgres", connStr)

	if err != nil {
		log.WithError(err).Fatal("Failed to connect to database")
		return nil, err
	}

	if err := db.Ping(); err != nil {
		log.WithError(err).Fatal("Failed to ping the database")
		return nil, err
	}

	return &Context{
		db: db,
	}, err
}

// FetchUsers fetches users from the database and returns them
func (auth *Context) FetchUsers() ([]*User, error) {
	rows, err := auth.db.Query("SELECT id, username from users")
	defer rows.Close()

	if err != nil {
		log.WithError(err).Error("SELECT users failed")
		return nil, err
	}

	users := make([]*User, 0)
	for rows.Next() {
		var userID int64
		var username string
		if err := rows.Scan(&userID, &username); err != nil {
			log.WithError(err).Error("Users row iteration failed")
			break
		}
		users = append(users, &User{ID: userID, Username: username})
	}

	return users, nil
}

// FetchSites fetches sites from the database and returns them
func (auth *Context) FetchSites() ([]*Site, error) {
	rows, err := auth.db.Query("SELECT id, url from sites")
	defer rows.Close()

	if err != nil {
		log.WithError(err).Error("SELECT sites failed")
		return nil, err
	}

	sites := make([]*Site, 0)
	for rows.Next() {
		var siteID int64
		var URL string
		if err := rows.Scan(&siteID, &URL); err != nil {
			log.WithError(err).Error("Sites row iteration failed")
			break
		}
		sites = append(sites, &Site{ID: siteID, URL: URL})
	}

	return sites, nil
}

// FetchClaims fetches the Username/URL combination of a claim and returns it
func (auth *Context) FetchClaims() ([]*Claim, error) {
	rows, err := auth.db.Query("select username, url from claims join users on users.id=user_id join sites on sites.id=site_id")
	defer rows.Close()

	if err != nil {
		log.WithError(err).Error("SELECT claims failed")
		return nil, err
	}

	claims := make([]*Claim, 0)
	for rows.Next() {
		var username string
		var URL string
		if err := rows.Scan(&username, &URL); err != nil {
			log.WithError(err).Error("Claims row iteration failed")
			break
		}
		claims = append(claims, &Claim{Username: username, URL: URL})
	}

	return claims, nil
}

// AuthenticateUser authenticates a user against its credentials in the database
func (auth *Context) AuthenticateUser(username, password string) bool {
	rows, err := auth.db.Query("select salt, password from users where username = $1", username)
	defer rows.Close()

	if err != nil {
		log.WithError(err).Error("Failed to execute auth query")
		return false
	}

	if ok := rows.Next(); !ok {
		log.WithError(rows.Err()).Error("Failed to retrieve user record from row")
		return false
	}

	var (
		hash string
		salt string
	)

	if err := rows.Scan(&salt, &hash); err != nil {
		log.WithError(err).Error("Failed to unmarshal row to variables")
		return false
	}

	return fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s%s", salt, password)))) == hash
}

// AuthenticateAdmin authenticates a user against its credentials in the database and verifies that is's an administrator
func (auth *Context) AuthenticateAdmin(username, password string) bool {
	rows, err := auth.db.Query("select salt, password, admin from users where username = $1", username)
	defer rows.Close()

	if err != nil {
		log.WithError(err).Error("Failed to execute auth query")
		return false
	}

	if ok := rows.Next(); !ok {
		log.WithError(rows.Err()).Error("Failed to retrieve user record from row")
		return false
	}

	var (
		hash  string
		salt  string
		admin bool
	)

	if err := rows.Scan(&salt, &hash, &admin); err != nil {
		log.WithError(err).Error("Failed to unmarshal row to variables")
		return false
	}

	return fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s%s", salt, password)))) == hash && admin
}

// AddUser adds a new user to the database
func (auth *Context) AddUser(username, password string) error {
	saltSrc, err := uuid.NewRandom()

	if err != nil {
		log.WithError(err).Error("Failed to create a new random uuid4")
		return err
	}

	salt := fmt.Sprintf("%x", sha256.Sum256([]byte(saltSrc.String())))
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s%s", salt, password))))

	stmt, err := auth.db.Prepare("INSERT INTO users (username, password, salt) VALUES ($1, $2, $3)")

	if err != nil {
		log.WithError(err).Error("Failed to initialize prepared statement")
		return err
	}

	_, err = stmt.Exec(username, hash, salt)
	if err != nil {
		log.WithError(err).Error("Failed to execute instert user statement")
		return err
	}

	return nil
}

// AddSite adds a new site to the database
func (auth *Context) AddSite(url string) error {
	stmt, err := auth.db.Prepare("INSERT INTO sites (url) VALUES ($1)")

	if err != nil {
		log.WithError(err).Error("Failed to initialize prepared statement")
		return err
	}

	_, err = stmt.Exec(url)
	if err != nil {
		log.WithError(err).Error("Failed to execute instert site statement")
		return err
	}

	return nil
}

// AddClaim adds a new claim to the database, using the username and URL
func (auth *Context) AddClaim(username, url string) error {
	tx, err := auth.db.Begin()

	if err != nil {
		log.WithError(err).Error("Failed to init transaction")
		return err
	}

	// Fetch user
	// Abort if user not exists

	// Fetch site
	// Add site if not exists

	// Add claim
	stmt, err := tx.Prepare("INSERT INTO claims (user_id, site_id) VALUES ($1, $2)")

	if err != nil {
		log.WithError(err).Error("Failed to initialize prepared statement")
		tx.Rollback()
		return err
	}

	_, err = stmt.Exec(username, url)
	if err != nil {
		log.WithError(err).Error("Failed to execute instert claim statement")
		tx.Rollback()
		return err
	}

	if err := tx.Commit(); err != nil {
		log.WithError(err).Error("Failed to commit")
		tx.Rollback()
	}

	return nil
}

// CreateCSRFToken creates a CSRF token
func CreateCSRFToken() string {
	saltSrc, _ := uuid.NewRandom()

	return fmt.Sprintf("%x", sha256.Sum256([]byte(saltSrc.String())))
}
