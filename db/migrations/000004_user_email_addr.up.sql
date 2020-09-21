ALTER TABLE users ADD COLUMN email text default('') not null;
ALTER TABLE users ADD COLUMN email_verified boolean default(false) not null;
