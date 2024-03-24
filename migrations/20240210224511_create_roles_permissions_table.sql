CREATE TABLE IF NOT EXISTS roles (
    uid UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) NOT NULL UNIQUE
);
CREATE INDEX idx_roles_uid ON roles (uid);

CREATE TABLE IF NOT EXISTS permissions (
    uid UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) NOT NULL UNIQUE
);
CREATE INDEX idx_permissions_uid ON permissions (uid);

CREATE TABLE IF NOT EXISTS users_roles (
    user_uid UUID REFERENCES users(uid),
    role_uid UUID REFERENCES roles(uid),
    PRIMARY KEY (user_uid, role_uid)
);
CREATE INDEX idx_users_roles_uid ON users_roles (user_uid, role_uid);


CREATE TABLE IF NOT EXISTS roles_permissions (
    role_uid UUID REFERENCES roles(uid),
    permission_uid UUID REFERENCES permissions(uid),
    primary key (role_uid, permission_uid)
);
CREATE INDEX idx_roles_permissions_uid ON roles_permissions (role_uid, permission_uid);


----------------- Seeding --------------
insert INTO roles (name)
VALUES ('users'),('admins');

insert into permissions (name)
VALUES ('dashboard.read'), ('restricted.read');

INSERT INTO roles_permissions (role_uid, permission_uid)
VALUES (
    (SELECT uid FROM roles WHERE name = 'users'),
    (SELECT uid FROM permissions WHERE name = 'dashboard.read')
), (
    (SELECT uid FROM roles WHERE name = 'admins'),
    (SELECT uid FROM permissions WHERE name = 'dashboard.read')
);

INSERT INTO users_roles (user_uid, role_uid)
VALUES (
    (SELECT uid FROM users WHERE username = 'ferris'),
    (select uid FROM roles WHERE name = 'users')
), (
    (SELECT uid FROM users WHERE username = 'admin'),
    (SELECT uid FROM roles WHERE name = 'users')
), (
    (SELECT uid FROM users WHERE username = 'admin'),
    (SELECT uid FROM roles WHERE name = 'admins')
);