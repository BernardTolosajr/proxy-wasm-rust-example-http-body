use std::f32::consts::E;

use proxy_wasm::traits::*;
use proxy_wasm::types::*;
use log::info;
use json;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Trace);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(HttpBodyRoot {
        configuration: PluginConfiguration { key: String::new() }
    }) });
}}

struct HttpBodyRoot {
    configuration: PluginConfiguration
}

impl Context for HttpBodyRoot {}

impl RootContext for HttpBodyRoot {
    fn on_configure(&mut self, _plugin_configuration_size: usize) -> bool {
        if let Some(config_bytes) = self.get_plugin_configuration() {
            let config_str = String::from_utf8(config_bytes).unwrap();     
            let json_value =  match json::parse(&config_str) {
                Ok(value) => value,
                Err(err) => {
                    log::error!("{}",err);
                    json::parse("{}").unwrap()
                }
            };
            let key = &json_value["key"];
            self.configuration = PluginConfiguration {
                key: key.to_string(),
            };
            info!("loaded configuration {:?}", self.configuration)
        }
        true
    }
    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    fn create_http_context(&self, context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(HttpBody {
            context_id,
            total_request_body_size: 0,
            configuration: self.configuration.clone()
        }))
    }
}

struct HttpBody {
    context_id: u32,
    total_request_body_size: usize,
    configuration: PluginConfiguration
}

impl Context for HttpBody {
}

impl HttpBody {
    fn validate_payload(&mut self, json_value: &json::JsonValue) -> bool {
        json_value.has_key("foo")
    }
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
            if !self.validate_payload(&json_value) {
                // If the validation fails, send the 403 response,
                self.send_http_response(
                    403,
                    vec![("Powered-By", "proxy-wasm")],
                    Some(b"Not allowed!\n"));
                // and terminates this traffic.
                return  Action::Pause;
            }
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

        // Since we returned "Pause" previuously, this will return the whole body.
        if let Some(body_bytes) = self.get_http_response_body(0, body_size) {
            let body_str = String::from_utf8(body_bytes).unwrap();
            info!("response: {}", body_str);
            //self.set_http_response_body(0, body_size, &body_str.into_bytes());
        }
        Action::Continue
    }
}

// pluginConfiguration is a type to represent an example configuration for this wasm plugin.
#[derive(Clone, Debug)]
struct PluginConfiguration {
	// Example configuration field.
	// The plugin will validate if those fields exist in the json payload.
    key: String
}