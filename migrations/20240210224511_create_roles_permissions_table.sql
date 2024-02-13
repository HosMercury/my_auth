CREATE TABLE IF NOT EXISTS roles (
    id SERIAl PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS permissions (
    id SERIAl PRIMARY KEY,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS users_roles (
    user_id UUID REFERENCES users(id),
    role_id INTEGER REFERENCES roles(id),
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE IF NOT EXISTS roles_permissions (
    role_id INTEGER REFERENCES roles(id),
    permission_id INTEGER REFERENCES permissions(id),
    primary key (role_id, permission_id)
);

----------------- Seeding --------------
insert INTO roles (name)
VALUES ('users'),('admins');

insert into permissions (name)
VALUES ('dashboard.read'), ('restricted.read');

INSERT INTO roles_permissions (role_id, permission_id)
VALUES (
    (SELECT id FROM roles WHERE name = 'users'),
    (SELECT id FROM permissions WHERE name = 'dashboard.read')
), (
    (SELECT id FROM roles WHERE name = 'admins'),
    (SELECT id FROM permissions WHERE name = 'dashboard.read')
);

INSERT INTO users_roles (user_id, role_id)
VALUES (
    (SELECT id FROM users WHERE username = 'ferris'),
    (select id FROM roles WHERE name = 'users')
), (
    (SELECT id FROM users WHERE username = 'admin'),
    (SELECT id FROM roles WHERE name = 'users')
), (
    (SELECT id FROM users WHERE username = 'admin'),
    (SELECT id FROM roles WHERE name = 'admins')
);