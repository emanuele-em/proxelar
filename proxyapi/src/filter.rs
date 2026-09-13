//! Flow filter expression language shared by user interfaces and API clients.
//!
//! Supported terms include `host:example.com`, `method:POST`, `status:404`,
//! `type:json`, `body:error`, `header:x-trace`, and mitmproxy-style aliases
//! such as `~d`, `~m`, `~s`, `~t`, and `~b`. Combine terms with `&`, `|`,
//! `!`, and parentheses. Adjacent terms imply AND.

use std::fmt;

use proxyapi_models::{
    CapturedDnsExchange, CapturedTcpStream, CapturedUdpExchange, ProxiedRequest, ProxiedResponse,
    WsFrame,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowFilter {
    expression: Expression,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Expression {
    MatchAll,
    Term(Term),
    Not(Box<Self>),
    And(Box<Self>, Box<Self>),
    Or(Box<Self>, Box<Self>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Term {
    field: Field,
    needle: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Field {
    Any,
    Time,
    Proto,
    Method,
    Host,
    Path,
    Url,
    Status,
    ContentType,
    Size,
    Duration,
    Body,
    RequestBody,
    ResponseBody,
    Header,
    RequestHeader,
    ResponseHeader,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Token {
    Word(String),
    And,
    Or,
    Not,
    LeftParen,
    RightParen,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FilterParseError {
    message: String,
}

impl FilterParseError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for FilterParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for FilterParseError {}

impl FlowFilter {
    pub fn parse(input: &str) -> Result<Self, FilterParseError> {
        let tokens = tokenize(input)?;
        if tokens.is_empty() {
            return Ok(Self {
                expression: Expression::MatchAll,
            });
        }
        let mut parser = Parser { tokens, cursor: 0 };
        let expression = parser.parse_or()?;
        if parser.peek().is_some() {
            return Err(FilterParseError::new(
                "unexpected token after filter expression",
            ));
        }
        Ok(Self { expression })
    }

    pub fn matches(
        &self,
        request: &ProxiedRequest,
        response: Option<&ProxiedResponse>,
        websocket: bool,
    ) -> bool {
        self.expression.matches(request, response, websocket)
    }

    pub fn matches_tcp(&self, stream: &CapturedTcpStream) -> bool {
        self.expression.matches_tcp(stream)
    }

    pub fn matches_websocket(
        &self,
        request: &ProxiedRequest,
        response: &ProxiedResponse,
        frames: &[WsFrame],
        closed: bool,
    ) -> bool {
        self.expression
            .matches_websocket(request, response, frames, closed)
    }

    pub fn matches_dns(&self, exchange: &CapturedDnsExchange) -> bool {
        self.expression.matches_dns(exchange)
    }

    pub fn matches_udp(&self, exchange: &CapturedUdpExchange) -> bool {
        self.expression.matches_udp(exchange)
    }
}

impl Expression {
    fn matches(
        &self,
        request: &ProxiedRequest,
        response: Option<&ProxiedResponse>,
        websocket: bool,
    ) -> bool {
        match self {
            Self::MatchAll => true,
            Self::Term(term) => term.matches(request, response, websocket),
            Self::Not(inner) => !inner.matches(request, response, websocket),
            Self::And(left, right) => {
                left.matches(request, response, websocket)
                    && right.matches(request, response, websocket)
            }
            Self::Or(left, right) => {
                left.matches(request, response, websocket)
                    || right.matches(request, response, websocket)
            }
        }
    }

    fn matches_tcp(&self, stream: &CapturedTcpStream) -> bool {
        match self {
            Self::MatchAll => true,
            Self::Term(term) => term.matches_tcp(stream),
            Self::Not(inner) => !inner.matches_tcp(stream),
            Self::And(left, right) => left.matches_tcp(stream) && right.matches_tcp(stream),
            Self::Or(left, right) => left.matches_tcp(stream) || right.matches_tcp(stream),
        }
    }

    fn matches_websocket(
        &self,
        request: &ProxiedRequest,
        response: &ProxiedResponse,
        frames: &[WsFrame],
        closed: bool,
    ) -> bool {
        match self {
            Self::MatchAll => true,
            Self::Term(term) => term.matches_websocket(request, response, frames, closed),
            Self::Not(inner) => !inner.matches_websocket(request, response, frames, closed),
            Self::And(left, right) => {
                left.matches_websocket(request, response, frames, closed)
                    && right.matches_websocket(request, response, frames, closed)
            }
            Self::Or(left, right) => {
                left.matches_websocket(request, response, frames, closed)
                    || right.matches_websocket(request, response, frames, closed)
            }
        }
    }

    fn matches_dns(&self, exchange: &CapturedDnsExchange) -> bool {
        match self {
            Self::MatchAll => true,
            Self::Term(term) => term.matches_dns(exchange),
            Self::Not(inner) => !inner.matches_dns(exchange),
            Self::And(left, right) => left.matches_dns(exchange) && right.matches_dns(exchange),
            Self::Or(left, right) => left.matches_dns(exchange) || right.matches_dns(exchange),
        }
    }

    fn matches_udp(&self, exchange: &CapturedUdpExchange) -> bool {
        match self {
            Self::MatchAll => true,
            Self::Term(term) => term.matches_udp(exchange),
            Self::Not(inner) => !inner.matches_udp(exchange),
            Self::And(left, right) => left.matches_udp(exchange) && right.matches_udp(exchange),
            Self::Or(left, right) => left.matches_udp(exchange) || right.matches_udp(exchange),
        }
    }
}

impl Term {
    fn matches(
        &self,
        request: &ProxiedRequest,
        response: Option<&ProxiedResponse>,
        websocket: bool,
    ) -> bool {
        let contains = |value: &str| value.to_ascii_lowercase().contains(&self.needle);
        match self.field {
            Field::Any => {
                contains(request.method().as_str())
                    || contains(&request.uri().to_string())
                    || headers_contain(request.headers(), &self.needle)
                    || bytes_contain(request.body(), &self.needle)
                    || response.is_some_and(|response| {
                        contains(&response.status().as_u16().to_string())
                            || headers_contain(response.headers(), &self.needle)
                            || bytes_contain(response.body(), &self.needle)
                    })
            }
            Field::Time => contains(&format_time(request.time())),
            Field::Proto => contains(protocol(request, websocket)),
            Field::Method => contains(if websocket {
                "GET"
            } else {
                request.method().as_str()
            }),
            Field::Host => contains(request.uri().host().unwrap_or("")),
            Field::Path => contains(request.uri().path()),
            Field::Url => contains(&request.uri().to_string()),
            Field::Status => {
                response.is_some_and(|response| contains(&response.status().as_u16().to_string()))
            }
            Field::ContentType => response.is_some_and(|response| {
                response
                    .headers()
                    .get(http::header::CONTENT_TYPE.as_str())
                    .and_then(|value| std::str::from_utf8(value).ok())
                    .is_some_and(contains)
            }),
            Field::Size => response.is_some_and(|response| {
                contains(&format_size(response.body_metadata().total_seen))
            }),
            Field::Duration => response.is_some_and(|response| {
                contains(&format_duration(
                    response.time().saturating_sub(request.time()),
                ))
            }),
            Field::Body => {
                bytes_contain(request.body(), &self.needle)
                    || response.is_some_and(|response| bytes_contain(response.body(), &self.needle))
            }
            Field::RequestBody => bytes_contain(request.body(), &self.needle),
            Field::ResponseBody => {
                response.is_some_and(|response| bytes_contain(response.body(), &self.needle))
            }
            Field::Header => {
                headers_contain(request.headers(), &self.needle)
                    || response
                        .is_some_and(|response| headers_contain(response.headers(), &self.needle))
            }
            Field::RequestHeader => headers_contain(request.headers(), &self.needle),
            Field::ResponseHeader => {
                response.is_some_and(|response| headers_contain(response.headers(), &self.needle))
            }
        }
    }

    fn matches_tcp(&self, stream: &CapturedTcpStream) -> bool {
        let contains = |value: &str| value.to_ascii_lowercase().contains(&self.needle);
        let payload_matches = || {
            stream
                .chunks
                .iter()
                .any(|chunk| bytes_contain(&chunk.payload, &self.needle))
        };
        match self.field {
            Field::Any => contains(&stream.target) || payload_matches(),
            Field::Time => contains(&format_time(stream.opened_at)),
            Field::Proto | Field::ContentType => contains("tcp binary"),
            Field::Host | Field::Path | Field::Url => contains(&stream.target),
            Field::Status => contains(if stream.closed { "closed" } else { "live" }),
            Field::Size => contains(&format_size(
                stream.chunks.iter().map(|chunk| chunk.payload.len()).sum(),
            )),
            Field::Body | Field::RequestBody | Field::ResponseBody => payload_matches(),
            Field::Header | Field::RequestHeader | Field::ResponseHeader | Field::Method => false,
            Field::Duration => false,
        }
    }

    fn matches_websocket(
        &self,
        request: &ProxiedRequest,
        response: &ProxiedResponse,
        frames: &[WsFrame],
        closed: bool,
    ) -> bool {
        let frame_matches = || {
            frames
                .iter()
                .any(|frame| bytes_contain(&frame.payload, &self.needle))
        };
        match self.field {
            Field::Any | Field::Body => {
                self.matches(request, Some(response), true) || frame_matches()
            }
            Field::Status => {
                self.matches(request, Some(response), true)
                    || if closed {
                        "closed".contains(&self.needle)
                    } else {
                        "live".contains(&self.needle)
                    }
            }
            _ => self.matches(request, Some(response), true),
        }
    }

    fn matches_dns(&self, exchange: &CapturedDnsExchange) -> bool {
        let contains = |value: &str| value.to_ascii_lowercase().contains(&self.needle);
        let answers = exchange.answers.join(" ");
        let query_type = dns_query_type(exchange.query_type);
        match self.field {
            Field::Any => contains(&exchange.name) || contains(&answers) || contains(query_type),
            Field::Time => contains(&format_time(exchange.time)),
            Field::Proto => contains("dns"),
            Field::Method | Field::ContentType => contains(query_type),
            Field::Host | Field::Path | Field::Url => contains(&exchange.name),
            Field::Status => contains(if !exchange.completed {
                "pending"
            } else if exchange.overridden {
                "override"
            } else {
                "upstream"
            }),
            Field::Size => contains(&format_size(answers.len())),
            Field::Body | Field::RequestBody | Field::ResponseBody => contains(&answers),
            Field::Header | Field::RequestHeader | Field::ResponseHeader | Field::Duration => false,
        }
    }

    fn matches_udp(&self, exchange: &CapturedUdpExchange) -> bool {
        let contains = |value: &str| value.to_ascii_lowercase().contains(&self.needle);
        match self.field {
            Field::Any => {
                contains(&exchange.target)
                    || contains(&exchange.client)
                    || bytes_contain(&exchange.request, &self.needle)
                    || bytes_contain(&exchange.response, &self.needle)
            }
            Field::Time => contains(&format_time(exchange.time)),
            Field::Proto => contains("udp"),
            Field::Method => contains("datagram"),
            Field::Host | Field::Path | Field::Url => contains(&exchange.target),
            Field::Status => contains(if exchange.response_received {
                "complete"
            } else {
                "no-response"
            }),
            Field::ContentType => contains("binary"),
            Field::Size => contains(&format_size(
                exchange.request.len() + exchange.response.len(),
            )),
            Field::Body => {
                bytes_contain(&exchange.request, &self.needle)
                    || bytes_contain(&exchange.response, &self.needle)
            }
            Field::RequestBody => bytes_contain(&exchange.request, &self.needle),
            Field::ResponseBody => bytes_contain(&exchange.response, &self.needle),
            Field::Header | Field::RequestHeader | Field::ResponseHeader | Field::Duration => false,
        }
    }
}

fn dns_query_type(query_type: u16) -> &'static str {
    match query_type {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        65 => "HTTPS",
        _ => "OTHER",
    }
}

fn protocol(request: &ProxiedRequest, websocket: bool) -> &'static str {
    match (request.uri().scheme_str(), websocket) {
        (Some("https"), true) | (Some("wss"), true) => "wss",
        (_, true) => "ws",
        (Some("https"), false) => "https",
        _ => "http",
    }
}

fn headers_contain(headers: &proxyapi_models::HeaderBlock, needle: &str) -> bool {
    headers.iter().any(|field| {
        String::from_utf8_lossy(field.name())
            .to_ascii_lowercase()
            .contains(needle)
            || String::from_utf8_lossy(field.value())
                .to_ascii_lowercase()
                .contains(needle)
    })
}

fn bytes_contain(bytes: &[u8], needle: &str) -> bool {
    String::from_utf8_lossy(bytes)
        .to_ascii_lowercase()
        .contains(needle)
}

fn format_time(millis: i64) -> String {
    use chrono::TimeZone as _;
    chrono::Local
        .timestamp_millis_opt(millis)
        .single()
        .map(|value| value.format("%H:%M:%S").to_string())
        .unwrap_or_default()
}

fn format_size(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{bytes}b")
    } else if bytes < 1024 * 1024 {
        format!("{:.1}kb", bytes as f64 / 1024.0)
    } else {
        format!("{:.1}mb", bytes as f64 / (1024.0 * 1024.0))
    }
}

fn format_duration(milliseconds: i64) -> String {
    if milliseconds >= 1000 {
        format!("{:.1}s", milliseconds as f64 / 1000.0)
    } else {
        format!("{milliseconds}ms")
    }
}

struct Parser {
    tokens: Vec<Token>,
    cursor: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.cursor)
    }

    fn next(&mut self) -> Option<Token> {
        let token = self.tokens.get(self.cursor).cloned();
        self.cursor += usize::from(token.is_some());
        token
    }

    fn parse_or(&mut self) -> Result<Expression, FilterParseError> {
        let mut expression = self.parse_and()?;
        while matches!(self.peek(), Some(Token::Or)) {
            self.next();
            expression = Expression::Or(Box::new(expression), Box::new(self.parse_and()?));
        }
        Ok(expression)
    }

    fn parse_and(&mut self) -> Result<Expression, FilterParseError> {
        let mut expression = self.parse_unary()?;
        loop {
            let explicit = matches!(self.peek(), Some(Token::And));
            if explicit {
                self.next();
            } else if !matches!(
                self.peek(),
                Some(Token::Word(_) | Token::Not | Token::LeftParen)
            ) {
                break;
            }
            expression = Expression::And(Box::new(expression), Box::new(self.parse_unary()?));
        }
        Ok(expression)
    }

    fn parse_unary(&mut self) -> Result<Expression, FilterParseError> {
        if matches!(self.peek(), Some(Token::Not)) {
            self.next();
            return Ok(Expression::Not(Box::new(self.parse_unary()?)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expression, FilterParseError> {
        match self.next() {
            Some(Token::LeftParen) => {
                let expression = self.parse_or()?;
                if !matches!(self.next(), Some(Token::RightParen)) {
                    return Err(FilterParseError::new("missing closing parenthesis"));
                }
                Ok(expression)
            }
            Some(Token::Word(word)) => self.parse_term(word).map(Expression::Term),
            Some(Token::RightParen) => Err(FilterParseError::new("unexpected closing parenthesis")),
            Some(Token::And | Token::Or) => Err(FilterParseError::new(
                "boolean operator is missing an operand",
            )),
            Some(Token::Not) => unreachable!("handled by parse_unary"),
            None => Err(FilterParseError::new(
                "filter expression ended unexpectedly",
            )),
        }
    }

    fn parse_term(&mut self, word: String) -> Result<Term, FilterParseError> {
        let alias = match word.as_str() {
            "~d" => Some(Field::Host),
            "~m" => Some(Field::Method),
            "~s" => Some(Field::Status),
            "~t" => Some(Field::ContentType),
            "~b" => Some(Field::Body),
            "~h" => Some(Field::Header),
            _ => None,
        };
        if let Some(field) = alias {
            let Some(Token::Word(value)) = self.next() else {
                return Err(FilterParseError::new(format!(
                    "filter alias {word} requires a value"
                )));
            };
            return Ok(Term {
                field,
                needle: value.to_ascii_lowercase(),
            });
        }

        let (field, value) = match word.split_once(':') {
            Some((name, value)) if parse_field(name).is_some() => {
                (parse_field(name).expect("checked above"), value)
            }
            _ => (Field::Any, word.as_str()),
        };
        if value.is_empty() {
            return Err(FilterParseError::new("filter term requires a value"));
        }
        Ok(Term {
            field,
            needle: value.to_ascii_lowercase(),
        })
    }
}

fn parse_field(name: &str) -> Option<Field> {
    match name.to_ascii_lowercase().as_str() {
        "time" => Some(Field::Time),
        "proto" | "protocol" => Some(Field::Proto),
        "method" => Some(Field::Method),
        "host" | "domain" => Some(Field::Host),
        "path" => Some(Field::Path),
        "url" | "uri" => Some(Field::Url),
        "status" | "status-code" | "status_code" => Some(Field::Status),
        "type" | "content-type" | "content_type" => Some(Field::ContentType),
        "size" => Some(Field::Size),
        "duration" | "time-ms" | "time_ms" => Some(Field::Duration),
        "body" => Some(Field::Body),
        "request-body" | "request_body" | "req-body" | "req_body" => Some(Field::RequestBody),
        "response-body" | "response_body" | "res-body" | "res_body" => Some(Field::ResponseBody),
        "header" => Some(Field::Header),
        "request-header" | "request_header" | "req-header" | "req_header" => {
            Some(Field::RequestHeader)
        }
        "response-header" | "response_header" | "res-header" | "res_header" => {
            Some(Field::ResponseHeader)
        }
        _ => None,
    }
}

fn tokenize(input: &str) -> Result<Vec<Token>, FilterParseError> {
    let mut tokens = Vec::new();
    let mut chars = input.char_indices().peekable();
    while let Some((_, character)) = chars.peek().copied() {
        if character.is_whitespace() {
            chars.next();
            continue;
        }
        match character {
            '&' => {
                chars.next();
                tokens.push(Token::And);
            }
            '|' => {
                chars.next();
                tokens.push(Token::Or);
            }
            '!' => {
                chars.next();
                tokens.push(Token::Not);
            }
            '(' => {
                chars.next();
                tokens.push(Token::LeftParen);
            }
            ')' => {
                chars.next();
                tokens.push(Token::RightParen);
            }
            quote @ ('"' | '\'') => {
                chars.next();
                let mut value = String::new();
                let mut closed = false;
                while let Some((_, current)) = chars.next() {
                    if current == quote {
                        closed = true;
                        break;
                    }
                    if current == '\\' {
                        if let Some((_, escaped)) = chars.next() {
                            value.push(escaped);
                        }
                    } else {
                        value.push(current);
                    }
                }
                if !closed {
                    return Err(FilterParseError::new("unterminated quoted filter value"));
                }
                tokens.push(Token::Word(value));
            }
            _ => {
                let mut value = String::new();
                while let Some((_, current)) = chars.peek().copied() {
                    if matches!(current, '"' | '\'') {
                        let quote = current;
                        chars.next();
                        let mut closed = false;
                        while let Some((_, quoted)) = chars.next() {
                            if quoted == quote {
                                closed = true;
                                break;
                            }
                            if quoted == '\\' {
                                if let Some((_, escaped)) = chars.next() {
                                    value.push(escaped);
                                }
                            } else {
                                value.push(quoted);
                            }
                        }
                        if !closed {
                            return Err(FilterParseError::new("unterminated quoted filter value"));
                        }
                        continue;
                    }
                    if current.is_whitespace() || matches!(current, '&' | '|' | '!' | '(' | ')') {
                        break;
                    }
                    value.push(current);
                    chars.next();
                }
                if !value.is_empty() {
                    tokens.push(Token::Word(value));
                }
            }
        }
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::{Method, StatusCode, Version};
    use proxyapi_models::HeaderBlock;

    fn exchange() -> (ProxiedRequest, ProxiedResponse) {
        let mut request_headers = HeaderBlock::new();
        request_headers.add("x-trace", "alpha").unwrap();
        let mut response_headers = HeaderBlock::new();
        response_headers
            .add("content-type", "application/json")
            .unwrap();
        (
            ProxiedRequest::new(
                Method::POST,
                "https://api.example.test/items?q=one".parse().unwrap(),
                Version::HTTP_11,
                request_headers,
                Bytes::from_static(b"request payload"),
                1_000,
            ),
            ProxiedResponse::new(
                StatusCode::CREATED,
                Version::HTTP_11,
                response_headers,
                Bytes::from_static(br#"{"result":"ok"}"#),
                2_500,
            ),
        )
    }

    #[test]
    fn parses_column_terms_aliases_and_boolean_operators() {
        let (request, response) = exchange();
        for filter in [
            "host:example.test & method:post",
            "~d example.test ~m POST",
            "status:201 & type:json & body:result",
            "header:x-trace & ! status:500",
            "(method:get | method:post) & proto:https",
            "duration:1.5s & size:15b",
        ] {
            let parsed = FlowFilter::parse(filter).unwrap();
            assert!(
                parsed.matches(&request, Some(&response), false),
                "filter should match: {filter}"
            );
        }
    }

    #[test]
    fn supports_quoted_values_and_rejects_invalid_expressions() {
        let (request, response) = exchange();
        assert!(FlowFilter::parse("body:'request payload'")
            .unwrap()
            .matches(&request, Some(&response), false));
        assert!(FlowFilter::parse("https://api.example.test/items")
            .unwrap()
            .matches(&request, Some(&response), false));
        for filter in ["(", "method:", "~d", "method:get |"] {
            assert!(FlowFilter::parse(filter).is_err(), "should reject {filter}");
        }
    }

    #[test]
    fn websocket_protocol_alias_matches_wss() {
        let (request, response) = exchange();
        assert!(FlowFilter::parse("proto:wss")
            .unwrap()
            .matches(&request, Some(&response), true));
        let frames = [WsFrame::new(
            proxyapi_models::WsDirection::ServerToClient,
            proxyapi_models::WsOpcode::Text,
            1_100,
            Bytes::from_static(b"socket error"),
            false,
        )];
        assert!(
            FlowFilter::parse("proto:wss & body:'socket error' & status:closed")
                .unwrap()
                .matches_websocket(&request, &response, &frames, true)
        );
    }

    #[test]
    fn filters_tcp_dns_and_udp_with_the_same_boolean_language() {
        let stream = CapturedTcpStream {
            id: 1,
            target: "cache.example.test:6379".to_owned(),
            opened_at: 1_000,
            chunks: vec![proxyapi_models::TcpChunk {
                direction: proxyapi_models::StreamDirection::ClientToServer,
                time: 1_001,
                payload: Bytes::from_static(b"SET key value"),
                truncated: false,
            }],
            closed: true,
        };
        assert!(FlowFilter::parse("proto:tcp & body:value & status:closed")
            .unwrap()
            .matches_tcp(&stream));

        let dns = CapturedDnsExchange {
            id: 2,
            name: "api.example.test".to_owned(),
            query_type: 1,
            time: 1_000,
            answers: vec!["127.0.0.1".to_owned()],
            overridden: true,
            completed: true,
        };
        assert!(FlowFilter::parse("proto:dns & method:a & body:127.0.0.1")
            .unwrap()
            .matches_dns(&dns));

        let udp = CapturedUdpExchange {
            id: 3,
            target: "127.0.0.1:9000".to_owned(),
            client: "127.0.0.1:50000".to_owned(),
            time: 1_000,
            request: Bytes::from_static(b"ping"),
            response: Bytes::new(),
            response_received: true,
            request_truncated: false,
            response_truncated: false,
        };
        assert!(FlowFilter::parse("proto:udp & body:ping & status:complete")
            .unwrap()
            .matches_udp(&udp));
    }

    #[test]
    fn covers_http_filter_fields_and_parser_edges() {
        let (request, base_response) = exchange();
        let mut response_headers = base_response.headers().clone();
        response_headers.add("x-result", "finished").unwrap();
        let response = ProxiedResponse::new_with_body_metadata(
            base_response.status(),
            base_response.version(),
            response_headers,
            base_response.body().clone(),
            base_response.body_metadata(),
            base_response.time(),
        );

        let matching = [
            "",
            "post",
            &format!("time:{}", format_time(request.time())),
            "proto:https",
            "method:post",
            "host:api.example",
            "path:/items",
            "url:q=one",
            "status:201",
            "type:application/json",
            &format!("size:{}", format_size(response.body_metadata().total_seen)),
            &format!(
                "duration:{}",
                format_duration(response.time().saturating_sub(request.time()))
            ),
            "body:payload",
            "request-body:request",
            "response-body:result",
            "header:x-result",
            "request-header:x-trace",
            "response-header:finished",
            "!(method:get | status:500)",
        ];
        for expression in matching {
            assert!(
                FlowFilter::parse(expression)
                    .unwrap()
                    .matches(&request, Some(&response), false),
                "filter should match: {expression}"
            );
        }

        for expression in [
            "status:201",
            "type:json",
            "response-body:result",
            "response-header:x-result",
        ] {
            assert!(
                !FlowFilter::parse(expression)
                    .unwrap()
                    .matches(&request, None, false),
                "filter should require a response: {expression}"
            );
        }
        assert!(FlowFilter::parse("method:get")
            .unwrap()
            .matches(&request, Some(&response), true));
        assert!(FlowFilter::parse("proto:ws").unwrap().matches(
            &ProxiedRequest::new(
                Method::GET,
                "http://example.test/socket".parse().unwrap(),
                Version::HTTP_11,
                HeaderBlock::new(),
                Bytes::new(),
                1,
            ),
            Some(&response),
            true,
        ));

        for invalid in [
            ")",
            "& value",
            "value )",
            "value &",
            "~h )",
            "\"unterminated",
            "body:'unterminated",
        ] {
            assert!(
                FlowFilter::parse(invalid).is_err(),
                "filter should reject: {invalid}"
            );
        }
        assert!(FlowFilter::parse(r#"body:"request \"payload\"""#).is_ok());
        assert!(!FlowFilter::parse("unknown:value").unwrap().matches(
            &request,
            Some(&response),
            false
        ));
    }

    #[test]
    fn covers_transport_filter_fields_and_helpers() {
        let stream = CapturedTcpStream {
            id: 1,
            target: "cache.example.test:6379".to_owned(),
            opened_at: 1_000,
            chunks: vec![proxyapi_models::TcpChunk {
                direction: proxyapi_models::StreamDirection::ClientToServer,
                time: 1_001,
                payload: Bytes::from_static(b"SET key value"),
                truncated: false,
            }],
            closed: false,
        };
        for expression in [
            "cache.example",
            &format!("time:{}", format_time(stream.opened_at)),
            "proto:tcp",
            "type:binary",
            "host:6379",
            "path:cache",
            "url:example",
            "status:live",
            &format!(
                "size:{}",
                format_size(stream.chunks.iter().map(|chunk| chunk.payload.len()).sum())
            ),
            "body:value",
            "request-body:key",
            "response-body:set",
        ] {
            assert!(
                FlowFilter::parse(expression).unwrap().matches_tcp(&stream),
                "TCP filter should match: {expression}"
            );
        }
        for expression in [
            "method:get",
            "header:value",
            "request-header:value",
            "response-header:value",
            "duration:1ms",
        ] {
            assert!(!FlowFilter::parse(expression).unwrap().matches_tcp(&stream));
        }

        let (request, response) = exchange();
        let frame = WsFrame::new(
            proxyapi_models::WsDirection::ClientToServer,
            proxyapi_models::WsOpcode::Binary,
            1_100,
            Bytes::from_static(b"frame payload"),
            false,
        );
        assert!(FlowFilter::parse("body:frame").unwrap().matches_websocket(
            &request,
            &response,
            &[frame],
            false
        ));
        assert!(FlowFilter::parse("status:live").unwrap().matches_websocket(
            &request,
            &response,
            &[],
            false
        ));

        for (query_type, label) in [
            (1, "a"),
            (2, "ns"),
            (5, "cname"),
            (12, "ptr"),
            (15, "mx"),
            (16, "txt"),
            (28, "aaaa"),
            (33, "srv"),
            (65, "https"),
            (255, "other"),
        ] {
            let dns = CapturedDnsExchange {
                id: 2,
                name: "api.example.test".to_owned(),
                query_type,
                time: 1_000,
                answers: vec!["127.0.0.1".to_owned()],
                overridden: false,
                completed: false,
            };
            assert!(FlowFilter::parse(&format!("method:{label}"))
                .unwrap()
                .matches_dns(&dns));
        }
        let mut dns = CapturedDnsExchange {
            id: 2,
            name: "api.example.test".to_owned(),
            query_type: 1,
            time: 1_000,
            answers: vec!["127.0.0.1".to_owned()],
            overridden: false,
            completed: false,
        };
        for expression in [
            &format!("time:{}", format_time(dns.time)),
            "host:api.example",
            "path:example",
            "url:api",
            "status:pending",
            "size:9b",
            "request-body:127.0.0.1",
            "response-body:127.0.0.1",
        ] {
            assert!(FlowFilter::parse(expression).unwrap().matches_dns(&dns));
        }
        for expression in [
            "header:any",
            "request-header:any",
            "response-header:any",
            "duration:1ms",
        ] {
            assert!(!FlowFilter::parse(expression).unwrap().matches_dns(&dns));
        }
        dns.completed = true;
        assert!(FlowFilter::parse("status:upstream")
            .unwrap()
            .matches_dns(&dns));
        dns.overridden = true;
        assert!(FlowFilter::parse("status:override")
            .unwrap()
            .matches_dns(&dns));

        let udp = CapturedUdpExchange {
            id: 3,
            target: "127.0.0.1:9000".to_owned(),
            client: "127.0.0.1:50000".to_owned(),
            time: 1_000,
            request: Bytes::from_static(b"ping"),
            response: Bytes::from_static(b"pong"),
            response_received: false,
            request_truncated: false,
            response_truncated: false,
        };
        for expression in [
            "50000",
            &format!("time:{}", format_time(udp.time)),
            "method:datagram",
            "host:9000",
            "path:127.0.0.1",
            "url:9000",
            "status:no-response",
            "type:binary",
            "size:8b",
            "body:pong",
            "request-body:ping",
            "response-body:pong",
        ] {
            assert!(FlowFilter::parse(expression).unwrap().matches_udp(&udp));
        }
        for expression in [
            "header:any",
            "request-header:any",
            "response-header:any",
            "duration:1ms",
        ] {
            assert!(!FlowFilter::parse(expression).unwrap().matches_udp(&udp));
        }

        assert_eq!(format_size(1_024), "1.0kb");
        assert_eq!(format_size(1_048_576), "1.0mb");
        assert_eq!(format_duration(999), "999ms");
        assert_eq!(format_duration(1_000), "1.0s");
    }
}
