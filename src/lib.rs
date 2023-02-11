use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use log::info;
use json;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(HttpBodyRoot) });
}}

struct HttpBodyRoot;
impl Context for HttpBodyRoot {}

impl RootContext for HttpBodyRoot {
    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    fn create_http_context(&self, context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(HttpBody { context_id, total_request_body_size: 0}))
    }
}

struct HttpBody {
    context_id: u32,
    total_request_body_size: usize,
}

impl Context for HttpBody {
}

impl HttpContext for HttpBody {
    fn on_http_request_headers(&mut self, _: usize, _: bool) -> Action {
        for (name, value) in &self.get_http_request_headers() {
            info!("header: #{} -> {}: {}", self.context_id, name, value);
        }
        if let Some(header) = self.get_http_request_header("content-type") {
            if header != "application/json" {
                self.send_http_response(
                    400,
                    vec![("Hello", "World"), ("Powered-By", "proxy-wasm")],
                    Some(b"bad request!\n"),
                );
                return Action::Pause
            }
        }
        Action::Continue
    }

    fn on_http_request_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
        self.total_request_body_size += body_size;
        if !end_of_stream {
            // Wait until we see the entire body to replace.
            return Action::Pause;
        }
        if let Some(body_bytes) = self.get_http_request_body(0, self.total_request_body_size) {
            let body_str = String::from_utf8(body_bytes).unwrap();
            let json_value = match json::parse(&body_str) {
                Ok(val) => val,
                Err(err) => {
                    log::error!("{}",err);
                    json::parse("{}").unwrap()
                }
            };
            info!("request: {} {}",self.context_id, json_value);
        }
        Action::Continue
    }

    fn on_http_response_headers(&mut self, _: usize, _: bool) -> Action {
        // If there is a Content-Length header and we change the length of
        // the body later, then clients will break. So remove it.
        // We must do this here, because once we exit this function we
        // can no longer modify the response headers.
        self.set_http_response_header("content-length", None);
        self.set_http_response_header("Powered-By", Some("proxy-wasm"));
        Action::Continue
    }

    fn on_http_response_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
        if !end_of_stream {
            // Wait -- we'll be called again when the complete body is buffered
            // at the host side.
            return Action::Pause;
        }

        // Replace the message body if it contains the text "secret".
        // Since we returned "Pause" previuously, this will return the whole body.
        if let Some(body_bytes) = self.get_http_response_body(0, body_size) {
            let body_str = String::from_utf8(body_bytes).unwrap();
            info!("response: {}", body_str);
            //self.set_http_response_body(0, body_size, &body_str.into_bytes());
        }
        Action::Continue
    }
}