CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id varchar(128) primary key,
    client_secret varchar(128),
    name varchar(255) not null,
    created_at timestamp with time zone not null,
    redirect_uris text not null,
    grants text,
    user_id integer not null,
    CONSTRAINT users_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id)
);
