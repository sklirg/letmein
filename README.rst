LetMeIn
=======

A simple AuthForwarder handler for the Traefik reverse proxy.
It might work for other reverse proxies as well, as it returns
HTTP status codes for authorization requests.

Rationale
=========

I wanted to avoid creating new passwords for the web services I host
and run, so I figured creating kind of an SSO with authorization
would be a nice exercise.

Requirements
============

A postgresql server with the following tables:

Users
-----

::

    lmi=> \d users
                                        Table "public.users"
    Column  |          Type          | Collation | Nullable |              Default
    ----------+------------------------+-----------+----------+-----------------------------------
    id       | integer                |           | not null | nextval('users_id_seq'::regclass)
    username | character varying(255) |           | not null |
    password | text                   |           | not null |
    salt     | text                   |           | not null |
    admin    | boolean                |           | not null | false
    Indexes:
        "id_user" PRIMARY KEY, btree (id)
        "username_unique" UNIQUE CONSTRAINT, btree (username)
    Referenced by:
        TABLE "claims" CONSTRAINT "claims_user_id_fkey" FOREIGN KEY (user_id) REFERENCES users(id)

Sites
-----

::

    lmi=> \d sites
                                Table "public.sites"
    Column |  Type   | Collation | Nullable |              Default
    --------+---------+-----------+----------+-----------------------------------
    id     | integer |           | not null | nextval('sites_id_seq'::regclass)
    url    | text    |           | not null |
    Indexes:
        "id_site" PRIMARY KEY, btree (id)
        "url_unique" UNIQUE CONSTRAINT, btree (url)
    Referenced by:
        TABLE "claims" CONSTRAINT "claims_site_id_fkey" FOREIGN KEY (site_id) REFERENCES sites(id)

Claims
------

::

    lmi=> \d claims
                Table "public.claims"
    Column  |  Type   | Collation | Nullable | Default
    ---------+---------+-----------+----------+---------
    user_id | integer |           | not null |
    site_id | integer |           | not null |
    Indexes:
        "claims_unique_user_url" UNIQUE CONSTRAINT, btree (user_id, site_id)
    Foreign-key constraints:
        "claims_site_id_fkey" FOREIGN KEY (site_id) REFERENCES sites(id)
        "claims_user_id_fkey" FOREIGN KEY (user_id) REFERENCES users(id)


And a traefik configuration similar to the following

::

    # Routers
    [http.routers]
    # The app to auth proxy
    [http.routers.my-router]
        rule = "Path(`/foo`)"
        middlewares = ["letmein"]
        service = "foo"

    # LetMeIn, the auth proxy - login view
    [http.routers.login]
        rule = "Path(`/login`)"
        service = "letmein"

    # Middlewares
    # Set up LetMeIn as an auth proxy
    [http.middlewares]
        [http.middlewares.letmein.forwardAuth]
        address = "http://[::1]:8003/auth"
        authResponseHeaders = ["X-Auth-User"]

    ## Services
    [http.services]
    [http.services.foo.loadBalancer]

        [[http.services.foo.loadBalancer.servers]]
        url = "http://foo/"

        # LetMeIn, the auth proxy - login view
        [[http.services.letmein.loadBalancer.servers]]
        url = "http://[::1]:8003/login"
