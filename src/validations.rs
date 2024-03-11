use std::{borrow::Cow, collections::HashMap};

use axum_messages::Messages;
use sqlx::{query, Pool, Postgres};
use validator::{ValidationError, ValidationErrors, ValidationErrorsKind};

pub async fn validation_errors(errs: &ValidationErrors) -> HashMap<&str, String> {
    let errors = errs.field_errors();
    let mut extracted_errors: HashMap<&str, String> = HashMap::new();

    errors.into_iter().for_each(|(field, errs)| {
        errs.into_iter().for_each(|e| {
            // println!("params {:?}", e.clone().params["min"]);
            //let params = e.clone().params;
            // println!("{:?}", e.clone().params);
            match e.code.as_ref() {
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
                    extracted_errors.insert(field, "this field is not valid".to_string());
                }
            }
        })
    });

    extracted_errors
}

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

////////////////////////////////// Unused //////////////////////////////
////////////////////////////////// Drafts /////////////////////////////
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
