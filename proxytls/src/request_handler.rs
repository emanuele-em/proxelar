use tokio::io::{self, AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Default, PartialEq)]
pub struct ClientRequest {
    pub method: ConnectMethod,
    header: Vec<String>,
    data_block: Vec<String>,
}

#[derive(Debug, Default, PartialEq)]
pub struct ConnectMethod {
    pub name: String,
    pub uri: String,
    version: String,
}

impl ConnectMethod {
    fn new(name: &str, uri: &str, version: &str) -> Self {
        Self {
            name: name.to_string(),
            uri: uri.to_string(),
            version: version.to_string(),
        }
    }
}

// HTTP response status
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Status
pub enum ServerResponse {
    BadRequest,
    Forbidden,
    MethodNotAllowed,
    Ok,
}

pub async fn send_response<W: AsyncWriteExt + Unpin>(
    mut writer: W,
    response: ServerResponse,
) -> io::Result<()> {
    let (code, message) = match response {
        ServerResponse::BadRequest => (400, "Bad Request"),
        ServerResponse::Forbidden => (403, "Forbidden"),
        ServerResponse::MethodNotAllowed => (405, "Method Not Allowed"),
        ServerResponse::Ok => (200, "OK"),
    };
    let message = format!("HTTP/1.1 {} {}\r\n\r\n", code as u32, message);
    writer.write_all(&message.into_bytes()).await
}

// Support "CONNECT" [1, 2] only.
// [1] https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/CONNECT
// [2] https://tools.ietf.org/html/rfc2817#section-5.2
pub async fn get_request<R: AsyncReadExt + Unpin>(mut reader: R) -> io::Result<ClientRequest> {
    // A reasonable HTTP header size for CONNECT

    println!("I'm in get_request");

    const MAX_REQUEST_SIZE: usize = 1024;
    let mut buf = [0; MAX_REQUEST_SIZE];
    let len = reader.read(&mut buf).await?;
    let request = std::str::from_utf8(&buf[..len])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    parse_request(request)
}

// Parse a typically HTTP client request. Works for "CONNECT" only now.
// [1]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Session#sending_a_client_request
fn parse_request(request: &str) -> io::Result<ClientRequest> {
    #[derive(PartialEq)]
    enum ParseState {
        Method,
        Header,
        DataBlock,
    }

    let mut parsed = ClientRequest::default();
    let mut state = ParseState::Method;

    let lines = request.split("\r\n").collect::<Vec<&str>>();
    let mut i = 0;
    while i < lines.len() {
        match state {
            ParseState::Method => {
                parsed.method = parse_method(lines[i])?;
                state = ParseState::Header;
            }
            ParseState::Header => {
                // The HTTP header ends with an "\r\n\r\n".
                // The pattern is "(parsed)\r\n(we are here)(unparsed)" if current line is empty.
                // The (unparsed) part could be a nothing, or a "\r\n(next unparsed)"
                if lines[i].is_empty() {
                    // If next line exists, pattern is "\r\n(next unparsed)". Otherwise, the parsing
                    // is finished (no next line). In this case, the request is incomplete since it
                    // doesn't contain a "\r\n\r\n" mark
                    let has_next_line = i + 1 < lines.len();
                    if has_next_line {
                        state = ParseState::DataBlock;
                    }
                } else {
                    parsed.header.push(lines[i].to_string());
                }
            }
            ParseState::DataBlock => {
                // skip the last line if it's empty
                if !lines[i].is_empty() || i < lines.len() - 1 {
                    parsed.data_block.push(lines[i].to_string());
                }
            }
        }
        i += 1;
    }

    if state == ParseState::DataBlock {
        Ok(parsed)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid request",
        ))
    }
}

fn parse_method(method: &str) -> io::Result<ConnectMethod> {
    let mut items = method.split(' ');
    let name = items.next().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "No method in client request")
    })?;
    let uri = items
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "No URI in client request"))?;
    let version = items.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "No HTTP protocol version in client request",
        )
    })?;
    Ok(ConnectMethod::new(name, uri, version))
}