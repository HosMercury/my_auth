# Rust My-Auth (Multi-Auth)

This is a binary project expired from [axum-login](https://github.com/maxcountryman/axum-login) with many added features to work as a starting point that have many things neede for a starting full-backend project.

### Authentication and authorization

- Username / Password Auth .
- Google OAuth2 .
- API authentication .
- Authorization ( roles and permissions ) .

## Installation

- Download the app .
- Run the project using `cargo-watch` . please install [cargo-watch](https://crates.io/crates/cargo-watch) .

```bash
cargo watch -x run
```

- SQLX migrate ( this crate uses _postgres_ ) , the migrations also auto-generated with compile or you could use this command .

```bash
sqlx migrate run --database-url postgres://db_user:db_password@127.0.0.1:5432/db_name

```

- Run Docker containers `docker composer up` . The crate contains a docker file for postgres db and redis ( used for sessions ) .
- Run tailwind `npx` to watch for `input.css` and generate `output.css`file. do not forget to install Node and node packages .
  ```
  npm install
  ```

```bash
npx tailwindcss -i ./assets/input.css -o ./assets/output.css --watch
```

## Full features

- Redis sessions ( axum-sessions crate ) .
- Username / Password Authentication .
- API Auth ( generating Api token key ) .
- Open OAuth ( Google OAuth ) .
- Web Auth and API extractors and middlewares .
- Validation ( validator crate with custom validators ) .
- Authorization ( roles and permissions ) .
- Flash messages ( axum-messages crate ) .
- Askama Templates for basic needed pages with ( datetime custom filter ) .
- Tailwind installed with some initial styling .
