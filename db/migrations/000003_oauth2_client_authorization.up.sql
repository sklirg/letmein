CREATE TABLE IF NOT EXISTS oauth_client_authorization (
    client_id varchar(128) not null,
    user_id integer not null,
    authorized_at timestamp with time zone not null,
    grants text,
    PRIMARY KEY (client_id, user_id),
    CONSTRAINT users_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id),
    CONSTRAINT clients_client_id_fkey FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id)
);
