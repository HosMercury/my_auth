# Rust My-Auth (Multi-Auth)

This is a binary project expired from [axum-login](https://github.com/maxcountryman/axum-login) and added more code to implent many other features to work as a starting point that have many things neede for a full-backend project.

### Authentication and authorization

- Username / Password Auth
- google OAuth2
- Api auth
- Authorization ( roles and permissions )

## Installation

- Download the app .
- Run the project using `cargo-watch` . please install [cargo-watch](https://crates.io/crates/cargo-watch) .

```bash
cargo watch -x run
```

- SQLX migrate ( this crate uses postgres) , the migrations also auto-generated with compile or you could use this command .

```bash
sqlx migrate run --database-url postgres://db_user:db_password@127.0.0.1:5432/db_name

```

- Run Docker containers `docker composer up` . The crate contains a docker file for postgres db and redis ( used for sessions ) .
- Run tailwid `npx` to watch for `input.css` and generate `output.css`file. do not forget to install Node and node packages .`npm i`

```bash
npx tailwindcss -i ./assets/input.css -o ./assets/output.css --watch
```

## Full features

- Redis sessions ( axum-sessions crate ) .
- Username / Password Authentication .
- Api Auth ( generating Api token key ) .
- Open OAuth ( Google OAuth ) .
- Web Auth and Api extractors and middlewares .
- Validation ( validator crate ) .
- Authorization ( roles and permissions ) .
- Flash messages ( axum-messages crate ) .
- Askama Templates for basic needed pages with time custom filter .
- Tailwind installed .
