CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(50) NOT NULL,
        username VARCHAR(50) UNIQUE,
        email VARCHAR(50) UNIQUE,
        password VARCHAR(250),
        access_token VARCHAR(250),
        refresh_token VARCHAR(250),
        provider VARCHAR(50) NOT NULL DEFAULT 'web',
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMPTZ,
        deleted_at TIMESTAMPTZ,
        last_sign TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );

CREATE INDEX idx_users_id ON users (id);

----------------- Seeding --------------
INSERT INTO
    users (name, username, password)
VALUES
    (
        'Ferris',
        'ferris',
        '$argon2id$v=19$m=19456,t=2,p=1$VE0e3g7DalWHgDwou3nuRA$uC6TER156UQpk0lNQ5+jHM0l5poVjPA1he/Tyn9J4Zw'
    ),
    (
        'John Doe',
        'admin',
        '$argon2id$v=19$m=19456,t=2,p=1$VE0e3g7DalWHgDwou3nuRA$uC6TER156UQpk0lNQ5+jHM0l5poVjPA1he/Tyn9J4Zw'
    );