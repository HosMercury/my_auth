use axum_messages::Messages;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{de::DeserializeOwned, Serialize};
use sqlx::{query, Pool, Postgres};
use std::{borrow::Cow, collections::HashMap, default::Default};
use tower_sessions::Session;
use validator::{ValidationError, ValidationErrors, ValidationErrorsKind};

pub const PREVIOUS_DATA_SESSION_KEY: &str = "previous_data";

lazy_static! {
    pub static ref REGEX_NAME: Regex = Regex::new(r"[a-zA-Z ]{8,50}$").unwrap();
    pub static ref REGEX_USERNAME: Regex = Regex::new(r"[a-zA-Z0-9_-]{8,50}$").unwrap();
}

//////////////////////// Old Data //////////////////////////
// Save payload data in session
pub async fn save_previous_data<T: Serialize>(payload: &T, session: &Session) {
    session
        .insert(PREVIOUS_DATA_SESSION_KEY, payload)
        .await
        .expect("failed to inset payload");
}

// Get payload data from session
pub async fn get_previous_data<T: DeserializeOwned + Default>(session: &Session) -> T {
    match session
        .get::<T>(PREVIOUS_DATA_SESSION_KEY)
        .await
        .expect("Faild to get payload from session")
    {
        Some(payload) => payload,
        None => T::default(),
    }
}

////////////////////////////// Flash Messages ////////////////////////////
// Get flash messages
pub fn get_messages(messages: Messages) -> Vec<String> {
    messages
        .into_iter()
        .map(|message| format!("{}", message))
        .collect::<Vec<_>>()
}

pub async fn validation_errors(errs: &ValidationErrors) -> HashMap<&str, String> {
    let errors = errs.field_errors();
    let mut extracted_errors: HashMap<&str, String> = HashMap::new();

    errors.into_iter().for_each(|(field, errs)| {
        errs.into_iter().for_each(|e| match e.code.as_ref() {
            "regex_name" => {
                extracted_errors.insert(
                    field,
                    t!("errors.invalid_name", field = t!(field),).to_string(),
                );
            }
            "regex_username" => {
                extracted_errors.insert(
                    field,
                    t!("errors.invalid_username", field = t!(field),).to_string(),
                );
            }
            "username_exists" => {
                extracted_errors.insert(
                    field,
                    t!("errors.username_exists", field = t!(field),).to_string(),
                );
            }
            "email_exists" => {
                extracted_errors.insert(
                    field,
                    t!("errors.email_exists", field = t!(field),).to_string(),
                );
            }
            "email" => {
                extracted_errors.insert(
                    field,
                    t!("errors.invalid_email", field = t!(field),).to_string(),
                );
            }
            "regex_passwords" => {
                extracted_errors.insert(
                    field,
                    t!("errors.invalid_password", field = t!(field),).to_string(),
                );
            }
            "must_match" => {
                extracted_errors.insert(
                    field,
                    t!("errors.must_match", field = t!(field),).to_string(),
                );
            }
            "min_length" => {
                extracted_errors.insert(
                    field,
                    t!(
                        "errors.min_length",
                        field = t!(field),
                        min = e.params["min"]
                    )
                    .to_string(),
                );
            }
            "max_length" => {
                extracted_errors.insert(
                    field,
                    t!(
                        "errors.max_length",
                        field = t!(field),
                        max = e.params["max"]
                    )
                    .to_string(),
                );
            }
            "range" => {
                extracted_errors.insert(
                    field,
                    t!(
                        "errors.range",
                        field = t!(field),
                        min = e.params["min"],
                        max = e.params["max"]
                    )
                    .to_string(),
                );
            }
            _ => {
                // Unknown code - just in case
                extracted_errors.insert(
                    field,
                    t!("errors.invalid_field", field = t!(field),).to_string(),
                );
            }
        })
    });

    extracted_errors
}

////////////////////////////////// Validation fns //////////////////////////////
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
        Err(ValidationError::new("Password Validation Failed"))
    }
}

pub async fn username_exists(username: String, pool: &Pool<Postgres>) -> bool {
    query!("SELECT username FROM users WHERE username = $1", username)
        .fetch_one(pool)
        .await
        .is_ok()
}

#[allow(unused)]
pub async fn email_exists(email: &str, pool: &Pool<Postgres>) -> bool {
    query!("SELECT email FROM users WHERE email = $1", email)
        .fetch_one(pool)
        .await
        .is_ok()
}

///////////////////////////////////////////////////////////////////////
////////////////////////////////// Drafts /////////////////////////////
///////////////////////////////////////////////////////////////////////
#[allow(unused)]
pub fn flatten_validation_errs<'a>(
    e: &'a ValidationErrors,
    new_errors: &'a mut ValidationErrors,
) -> &'a ValidationErrors {
    e.errors().into_iter().for_each(|(field, kind)| {
        // println!("{}", field);
        match kind {
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
        }
    });

    new_errors
}

#[allow(unused)]
pub async fn json_validatio_errors(errs: ValidationErrors) {
    let mut new_errs = ValidationErrors::new();

    let mut new_m: Vec<String> = Vec::new();

    let errs = flatten_validation_errs(&errs, &mut new_errs)
        .field_errors()
        .into_iter()
        .for_each(|(_, errs)| {
            errs.iter().for_each(|e| {
                let m = format!(
                    "{}",
                    e.message
                        .clone()
                        .unwrap_or(Cow::Borrowed("No valdation error message provided"))
                );
                new_m.push(m);
            })
        });
}

#[allow(unused)]
pub async fn flash_errors(errs: ValidationErrors, messages: Messages) {
    let mut new_errs = ValidationErrors::new();

    flatten_validation_errs(&errs, &mut new_errs)
        .field_errors()
        .into_iter()
        .for_each(|(field, errs)| {
            errs.into_iter().for_each(|e| {
                let ms = messages.clone();
                // println!("{:#?} - {}", field, e.message.clone().unwrap());
                ms.error(format!("{} - {}", field, e.message.clone().unwrap()));
            })
        });

    // println!("mmm {:?}", messages);
}

#[allow(unused)]
pub fn extract_errors(
    errors: HashMap<&'static str, ValidationErrorsKind>,
) -> HashMap<String, String> {
    let mut extracted_errs: HashMap<String, String> = HashMap::new();
    for (k, v) in errors {
        match v {
            ValidationErrorsKind::Struct(_) => {} // todo
            ValidationErrorsKind::List(_) => {}   // todo
            ValidationErrorsKind::Field(errs) => {
                for err in errs {
                    let msg = err.message.as_ref().unwrap();
                    extracted_errs.insert(k.to_string(), msg.to_string());
                }
            }
        }
    }
    extracted_errs
}

#[allow(unused)]
pub fn pretty_print(e: &ValidationErrors, depth: usize) {
    match format_args!("{:1$}", "", depth * 2) {
        indent => {
            e.errors()
                .iter()
                .for_each(|(field_name, error_kind)| match error_kind {
                    ValidationErrorsKind::Field(error_messages) => {
                        error_messages
                            .iter()
                            .for_each(|m| println!("{indent}  {m},"));
                    }
                    ValidationErrorsKind::Struct(nested) => {
                        pretty_print(nested, depth + 1);
                    }
                    ValidationErrorsKind::List(sub_array) => {
                        sub_array.iter().for_each(|(i, nested)| {
                            pretty_print(nested, depth + 2);
                        });
                    }
                });
        }
    }
}
