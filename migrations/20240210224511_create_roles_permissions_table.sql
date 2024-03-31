CREATE TABLE IF NOT EXISTS roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,        
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ
);
CREATE INDEX idx_roles_id ON roles (id);

CREATE TABLE IF NOT EXISTS permissions (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ 
);
CREATE INDEX idx_permissions_id ON permissions (id);

CREATE TABLE IF NOT EXISTS users_roles (
    user_id INT REFERENCES users(id),
    role_id INT REFERENCES roles(id),
    PRIMARY KEY (user_id, role_id)
);
CREATE INDEX idx_users_roles_id ON users_roles (user_id, role_id);


CREATE TABLE IF NOT EXISTS roles_permissions (
    role_id INT REFERENCES roles(id),
    permission_id INT REFERENCES permissions(id),
    primary key (role_id, permission_id)
);
CREATE INDEX idx_roles_permissions_id ON roles_permissions (role_id, permission_id);


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