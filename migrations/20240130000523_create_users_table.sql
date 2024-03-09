CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name TEXT NOT NULL,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password TEXT,
        locale TEXT DEFAULT 'en',
        access_token TEXT,
        refresh_token TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMPTZ,
        deleted_at TIMESTAMPTZ,
        last_sign TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

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