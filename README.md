# Rust My-Auth (Multi-Auth)

This is a binary project inspired from [axum-login](https://github.com/maxcountryman/axum-login) with many additional features to work as a starting project that have most features needed for a starting full-backend project.

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

- SQLX migrate ( this crate uses _postgres_ ) , the migrations also auto-generated with compile or you could use this command . please create a `.env` file that contains `DATABASE_URL` and `CLIENT_ID` and `CLIENT_SECRET` where you could get these credentials from google OAuth console .

```bash
sqlx migrate run --database-url postgres://db_user:db_password@127.0.0.1:5432/db_name

```

- Run Docker containers `docker composer up` . The crate contains a _docker-compose_ file for postgres DB and redis ( used for sessions ) containers .
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
- Web Auth and API including extractors and middlewares .
- Validation ( validator crate with custom validators ) .
- Authorization ( roles and permissions ) .
- Flash messages ( axum-messages crate ) .
- Askama HTML templates for basic needed pages with ( datetime custom filter ) .
- Tailwind installed with some initial styling .
- Internationalization ( rust-i18n crate) .
