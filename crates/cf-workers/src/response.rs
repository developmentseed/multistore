//! Response builder helpers for Cloudflare Workers.
//!
//! Provides conversion functions between multistore proxy types and
//! `web_sys::Response`, including header conversion utilities.

use http::HeaderMap;
use multistore::api::response::ErrorResponse;
use multistore::backend::ForwardResponse;
use multistore::proxy::GatewayResponse;
use multistore::route_handler::{ProxyResponseBody, ProxyResult};

/// Convert a `ProxyResult` (small buffered XML/JSON) to a `web_sys::Response`.
pub fn response_from_proxy_result(result: ProxyResult) -> web_sys::Response {
    let ws_headers = headers_to_js(&result.headers)
        .unwrap_or_else(|_| web_sys::Headers::new().unwrap());

    let resp_init = web_sys::ResponseInit::new();
    resp_init.set_status(result.status);
    resp_init.set_headers(&ws_headers.into());

    match result.body {
        ProxyResponseBody::Empty => {
            web_sys::Response::new_with_opt_str_and_init(None, &resp_init).unwrap()
        }
        ProxyResponseBody::Bytes(bytes) => {
            let uint8 = js_sys::Uint8Array::from(bytes.as_ref());
            web_sys::Response::new_with_opt_buffer_source_and_init(Some(&uint8), &resp_init)
                .unwrap()
        }
    }
}

/// Convert a `ForwardResponse<web_sys::Response>` into a `web_sys::Response`
/// for the client, preserving the backend's body stream (zero-copy).
pub fn response_from_forward(resp: ForwardResponse<web_sys::Response>) -> web_sys::Response {
    let ws_headers = headers_to_js(&resp.headers)
        .unwrap_or_else(|_| web_sys::Headers::new().unwrap());

    let resp_init = web_sys::ResponseInit::new();
    resp_init.set_status(resp.status);
    resp_init.set_headers(&ws_headers.into());

    web_sys::Response::new_with_opt_readable_stream_and_init(resp.body.body().as_ref(), &resp_init)
        .unwrap_or_else(|_| error_response(502, "Bad Gateway"))
}

/// Build a plain-text error response.
pub fn error_response(status: u16, message: &str) -> web_sys::Response {
    let init = web_sys::ResponseInit::new();
    init.set_status(status);
    web_sys::Response::new_with_opt_str_and_init(Some(message), &init)
        .unwrap_or_else(|_| web_sys::Response::new().unwrap())
}

/// Build an XML response with `content-type: application/xml`.
pub fn xml_response(status: u16, xml_body: &str) -> web_sys::Response {
    let init = web_sys::ResponseInit::new();
    init.set_status(status);

    let headers = web_sys::Headers::new().unwrap();
    let _ = headers.set("content-type", "application/xml");
    init.set_headers(&headers.into());

    web_sys::Response::new_with_opt_str_and_init(Some(xml_body), &init)
        .unwrap_or_else(|_| error_response(500, "Internal Server Error"))
}

/// Convert a [`GatewayResponse`] to a `web_sys::Response`.
pub fn response_from_gateway(response: GatewayResponse<web_sys::Response>) -> web_sys::Response {
    match response {
        GatewayResponse::Response(r) => response_from_proxy_result(r),
        GatewayResponse::Forward(r) => response_from_forward(r),
    }
}

/// Build an S3-compatible XML error response from an [`ErrorResponse`].
pub fn s3_error_response(status: u16, error: &ErrorResponse) -> web_sys::Response {
    xml_response(status, &error.to_xml())
}

// -- Header conversion helpers -----------------------------------------------

/// Convert `web_sys::Headers` to `http::HeaderMap` by iterating all entries.
pub fn headermap_from_js(ws_headers: &web_sys::Headers) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for entry in ws_headers.entries() {
        let Ok(pair) = entry else { continue };
        let arr: js_sys::Array = pair.into();
        let Some(key) = arr.get(0).as_string() else {
            continue;
        };
        let Some(value) = arr.get(1).as_string() else {
            continue;
        };
        let Ok(name) = http::header::HeaderName::from_bytes(key.as_bytes()) else {
            continue;
        };
        let Ok(val) = http::header::HeaderValue::from_str(&value) else {
            continue;
        };
        headers.append(name, val);
    }
    headers
}

/// Convert `http::HeaderMap` to `web_sys::Headers`.
pub fn headers_to_js(
    headers: &HeaderMap,
) -> std::result::Result<web_sys::Headers, wasm_bindgen::JsValue> {
    let ws = web_sys::Headers::new()?;
    for (key, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            ws.set(key.as_str(), v)?;
        }
    }
    Ok(ws)
}
