use lazy_static::lazy_static;
use regex::Regex;
use sqlx::{query, Pool, Postgres};
use std::collections::HashMap;
use validator::{ValidationError, ValidationErrors, ValidationErrorsKind};

lazy_static! {
    pub static ref REGEX_NAME: Regex = Regex::new(r"[a-zA-Z ]{8,50}$").unwrap();
    pub static ref REGEX_USERNAME: Regex = Regex::new(r"[a-zA-Z0-9_-]{8,50}$").unwrap();
}

// add Localized messages to validation errors
pub fn validation_messages(errors: &ValidationErrors) -> ValidationErrors {
    let mut locale_errors: ValidationErrors = ValidationErrors::new();

    errors.field_errors().into_iter().for_each(|(field, errs)| {
        errs.into_iter().for_each(|e| match e.code.as_ref() {
            "regex_name" => {
                locale_errors.add(
                    field,
                    ValidationError {
                        code: e.code.clone(),
                        message: t!("errors.invalid_name", field = t!(field)).into(),
                        params: HashMap::from([("field".into(), field.into())]),
                    },
                );
            }
            "regex_username" => {
                locale_errors.add(
                    field,
                    ValidationError {
                        code: e.code.clone(),
                        message: t!("errors.invalid_username", field = t!(field)).into(),
                        params: HashMap::from([("field".into(), field.into())]),
                    },
                );
            }
            "username_exists" => {
                locale_errors.add(
                    field,
                    ValidationError {
                        code: e.code.clone(),
                        message: t!("errors.username_exists", field = t!(field)).into(),
                        params: HashMap::from([("field".into(), field.into())]),
                    },
                );
            }
            "email_exists" => {
                locale_errors.add(
                    field,
                    ValidationError {
                        code: e.code.clone(),
                        message: t!("errors.email_exists", field = t!(field)).into(),
                        params: HashMap::from([("field".into(), field.into())]),
                    },
                );
            }
            "email" => {
                locale_errors.add(
                    field,
                    ValidationError {
                        code: e.code.clone(),
                        message: t!("errors.invalid_email", field = t!(field)).into(),
                        params: HashMap::from([("field".into(), field.into())]),
                    },
                );
            }
            "invalid_password" => {
                locale_errors.add(
                    field,
                    ValidationError {
                        code: e.code.clone(),
                        message: t!("errors.invalid_password", field = t!(field)).into(),
                        params: HashMap::from([("field".into(), field.into())]),
                    },
                );
            }
            "must_match" => {
                locale_errors.add(
                    field,
                    ValidationError {
                        code: e.code.clone(),
                        message: t!("errors.must_match", field = t!(field)).into(),
                        params: HashMap::from([("field".into(), field.into())]),
                    },
                );
            }
            "min_length" => {
                locale_errors.add(
                    field,
                    ValidationError {
                        code: e.code.clone(),
                        message: t!(
                            "errors.min_length",
                            field = t!(field),
                            min = e.params["min"]
                        )
                        .into(),
                        params: HashMap::from([("field".into(), field.into())]),
                    },
                );
            }
            "max_length" => {
                locale_errors.add(
                    field,
                    ValidationError {
                        code: e.code.clone(),
                        message: t!(
                            "errors.max_length",
                            field = t!(field),
                            max = e.params["max"]
                        )
                        .into(),
                        params: HashMap::from([("field".into(), field.into())]),
                    },
                );
            }
            "range" => {
                locale_errors.add(
                    field,
                    ValidationError {
                        code: e.code.clone(),
                        message: t!("errors.range", field = t!(field)).into(),
                        params: HashMap::from([("field".into(), field.into())]),
                    },
                );
            }
            _ => {
                // Unknown code - just in case
                locale_errors.add(
                    field,
                    ValidationError {
                        code: e.code.clone(),
                        message: t!("errors.invalid_field", field = t!(field)).into(),
                        params: HashMap::from([("field".into(), field.into())]),
                    },
                );
            }
        })
    });

    locale_errors
}

#[allow(unused)]
pub fn flatten_validation_errs<'a>(
    e: &'a ValidationErrors,
    new_errors: &'a mut ValidationErrors,
) -> &'a ValidationErrors {
    e.errors().into_iter().for_each(|(field, kind)| match kind {
        ValidationErrorsKind::Struct(errors) => {
            flatten_validation_errs(&*errors, new_errors);
        }
        ValidationErrorsKind::List(errors_list) => {
            errors_list.clone().into_iter().for_each(|(_, errors)| {
                flatten_validation_errs(&*errors, new_errors);
            });
        }
        ValidationErrorsKind::Field(errors) => {
            errors.into_iter().enumerate().for_each(|(_, error)| {
                new_errors.add(field, error.clone());
            });
        }
    });

    new_errors
}

////////////////////////////////// Validation fns //////////////////////////////
// No async needing so return Result to automatically merge with Validator
pub fn validate_password(password: &str) -> Result<(), ValidationError> {
    let mut has_whitespace = false;
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;

    for c in password.chars() {
        has_whitespace |= c.is_whitespace();
        has_lower |= c.is_lowercase();
        has_upper |= c.is_uppercase();
        has_digit |= c.is_ascii_digit();
    }

    if !has_whitespace && has_upper && has_lower && has_digit {
        Ok(())
    } else {
        Err(ValidationError::new("invalid_password"))
    }
}

pub async fn username_exists(username: &str, pool: &Pool<Postgres>) -> bool {
    query!("SELECT username FROM users WHERE username = $1", username)
        .fetch_one(pool)
        .await
        .is_ok()
}

pub async fn validate_username<'a>(
    errors: &'a mut ValidationErrors,
    username: &str,
    db: &Pool<Postgres>,
) -> &'a ValidationErrors {
    if username_exists(username, db).await {
        errors.add(
            "username",
            ValidationError {
                code: "username_exists".into(),
                message: Some(t!("username_exists").into()),
                params: HashMap::from([("username".into(), username.into())]),
            },
        )
    }
    errors
}
pub async fn email_exists(email: &str, pool: &Pool<Postgres>) -> bool {
    query!("SELECT email FROM users WHERE email = $1", email)
        .fetch_one(pool)
        .await
        .is_ok()
}

pub async fn validate_email_exists(
    mut errors: ValidationErrors,
    email: &str,
    db: &Pool<Postgres>,
) -> ValidationErrors {
    if email_exists(email, db).await {
        errors.add(
            "email",
            ValidationError {
                code: "email_exists".into(),
                message: Some(t!("email_exists").into()),
                params: HashMap::from([("value".into(), email.into())]),
            },
        )
    }
    errors
}
