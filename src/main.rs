use goose::prelude::*;
use log::{error, info};
use serde::Deserialize;
use std::time::Duration;

struct Session {
    jwt_token: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticationResponse {
    data: AuthData,
}

#[derive(Deserialize)]
struct AuthData {
    access_token: String,
}

#[tokio::main]
async fn main() -> Result<(), GooseError> {
    GooseAttack::initialize()?
        .register_scenario(
            scenario!("PIITest")
                .set_wait_time(Duration::from_secs(5), Duration::from_secs(15))?
                // This transaction only runs one time when the user first starts.
                .register_transaction(transaction!(login).set_on_start())
                // These next two transactions run repeatedly as long as the load test is running.
                .register_transaction(transaction!(profile_dashboard)),
        )
        .execute()
        .await?;

    Ok(())
}

async fn login(user: &mut GooseUser) -> TransactionResult {
    let params = [("username", ""), ("password", "")];
    // Logging the request to login
    info!("Sending login request with username: {}", params[0].1);

    // Send login request
    let response = user.post_form("/login", &params).await?;

    // Handle and log response
    match response.response {
        Ok(r) => match r.json::<AuthenticationResponse>().await {
            Ok(auth_response) => {
                // Log the successful response
                info!(
                    "Login successful: JWT received {}",
                    auth_response.data.access_token
                );

                // Store the JWT token in the session data
                user.set_session_data(Session {
                    jwt_token: auth_response.data.access_token,
                });
            }
            Err(e) => {
                error!("Failed to parse login response: {:?}", e);
                return Err(Box::new(e.into()));
            }
        },
        Err(e) => {
            error!("Login request failed: {:?}", e);
            return Err(Box::new(e.into()));
        }
    }

    Ok(())
}

// Profile dashboard transaction: uses the JWT token to access the profile API
async fn profile_dashboard(user: &mut GooseUser) -> TransactionResult {
    // Retrieve the JWT token from the session
    let session = user.get_session_data_unchecked::<Session>();

    // Log the request for the profile dashboard
    info!("Requesting profile with JWT: {}", session.jwt_token);

    // Build the request for the profile API with the Bearer token
    let reqwest_request_builder = user
        .get_request_builder(&GooseMethod::Get, "")?
        .bearer_auth(&session.jwt_token);

    // Create a Goose request object with the request builder
    let goose_request = GooseRequest::builder()
        .set_request_builder(reqwest_request_builder)
        .build();

    // Send the request
    let response = user.request(goose_request).await?;

    // Log the response status
    if response.response.is_ok() {
        info!(
            "Profile request succeeded with status: {}",
            response.response.unwrap().status()
        );
    } else {
        error!(
            "Merchant Financing Submit request failed: {:?}",
            response.response.err()
        );
    }

    Ok(())
}
