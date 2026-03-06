//! Axum response helpers for converting core proxy types into axum responses.

use axum::body::Body;
use axum::response::Response;

use multistore::proxy::ProxyResult;
use multistore::response_body::ProxyResponseBody;

/// Convert a [`ProxyResult`] to an axum [`Response`].
pub fn build_proxy_response(result: ProxyResult) -> Response {
    let body = match result.body {
        ProxyResponseBody::Bytes(b) => Body::from(b),
        ProxyResponseBody::Empty => Body::empty(),
    };

    let mut builder = Response::builder().status(result.status);
    for (key, value) in result.headers.iter() {
        builder = builder.header(key, value);
    }

    builder.body(body).unwrap()
}

/// Build a plain-text error response.
pub fn error_response(status: u16, message: &str) -> Response {
    Response::builder()
        .status(status)
        .body(Body::from(message.to_string()))
        .unwrap()
}
