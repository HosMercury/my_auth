CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name TEXT NOT NULL,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT,
        access_token TEXT,
        refresh_token TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMPTZ,
        deleted_at TIMESTAMPTZ,
        last_login TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

----------------- Seeding --------------
INSERT INTO
    users (name, username, email, password)
VALUES
    (
        'Ferris',
        'ferris',
        'ferris@example.com',
        '$argon2id$v=19$m=19456,t=2,p=1$VE0e3g7DalWHgDwou3nuRA$uC6TER156UQpk0lNQ5+jHM0l5poVjPA1he/Tyn9J4Zw'
    ),
    (
        'John Doe',
        'admin',
        'admin@admin.com',
        '$argon2id$v=19$m=19456,t=2,p=1$VE0e3g7DalWHgDwou3nuRA$uC6TER156UQpk0lNQ5+jHM0l5poVjPA1he/Tyn9J4Zw'
    );