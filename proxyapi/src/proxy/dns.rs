use rama::telemetry::tracing;
use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::event::{next_id, ProxyEvent};
use crate::handler::now_millis;

#[derive(Clone, Debug)]
pub struct DnsConfig {
    pub upstream: SocketAddr,
    pub overrides: HashMap<String, IpAddr>,
    pub ttl: u32,
}

impl DnsConfig {
    pub fn new(upstream: SocketAddr) -> Self {
        Self {
            upstream,
            overrides: HashMap::new(),
            ttl: 30,
        }
    }

    pub fn add_override(&mut self, name: impl Into<String>, address: IpAddr) {
        self.overrides.insert(
            name.into().trim_end_matches('.').to_ascii_lowercase(),
            address,
        );
    }
}

pub async fn serve(
    address: SocketAddr,
    config: DnsConfig,
    event_tx: mpsc::Sender<ProxyEvent>,
    shutdown: impl Future<Output = ()>,
) -> std::io::Result<()> {
    let socket = Arc::new(UdpSocket::bind(address).await?);
    tracing::info!(
        "DNS proxy listening on {address}, upstream {}",
        config.upstream
    );
    tokio::pin!(shutdown);
    let mut buffer = vec![0_u8; 65_535];
    loop {
        tokio::select! {
            received = socket.recv_from(&mut buffer) => {
                let (length, client) = received?;
                let packet = buffer[..length].to_vec();
                let socket = Arc::clone(&socket);
                let config = config.clone();
                let event_tx = event_tx.clone();
                tokio::spawn(async move {
                    if let Err(error) = handle_packet(socket, client, packet, config, event_tx).await {
                        tracing::debug!("DNS request failed: {error}");
                    }
                });
            }
            () = &mut shutdown => return Ok(()),
        }
    }
}

async fn handle_packet(
    socket: Arc<UdpSocket>,
    client: SocketAddr,
    packet: Vec<u8>,
    config: DnsConfig,
    event_tx: mpsc::Sender<ProxyEvent>,
) -> std::io::Result<()> {
    let response = resolve_packet(packet, config, event_tx).await?;
    socket.send_to(&response, client).await?;
    Ok(())
}

pub(crate) async fn resolve_packet(
    packet: Vec<u8>,
    config: DnsConfig,
    event_tx: mpsc::Sender<ProxyEvent>,
) -> std::io::Result<Vec<u8>> {
    let query = parse_query(&packet)?;
    let id = next_id();
    let _ = event_tx.try_send(ProxyEvent::DnsQuery {
        id,
        name: query.name.clone(),
        query_type: query.query_type,
        time: now_millis(),
    });
    let override_address = config
        .overrides
        .get(&query.name.trim_end_matches('.').to_ascii_lowercase())
        .copied()
        .filter(|address| {
            matches!(
                (query.query_type, address),
                (1, IpAddr::V4(_)) | (28, IpAddr::V6(_))
            )
        });
    let (response, answers, overridden) = if let Some(address) = override_address {
        (
            override_response(&packet, &query, address, config.ttl)?,
            vec![address.to_string()],
            true,
        )
    } else {
        let response = forward(&packet, config.upstream).await?;
        let answers = parse_answers(&response).unwrap_or_default();
        (response, answers, false)
    };
    let _ = event_tx.try_send(ProxyEvent::DnsResponse {
        id,
        answers,
        overridden,
    });
    Ok(response)
}

async fn forward(packet: &[u8], upstream: SocketAddr) -> std::io::Result<Vec<u8>> {
    let bind_address = if upstream.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind_address).await?;
    socket.connect(upstream).await?;
    socket.send(packet).await?;
    let mut response = vec![0_u8; 65_535];
    let length = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut response))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "DNS upstream timeout"))??;
    response.truncate(length);
    Ok(response)
}

struct Query {
    name: String,
    query_type: u16,
    question_end: usize,
}

fn parse_query(packet: &[u8]) -> std::io::Result<Query> {
    if packet.len() < 17 {
        return Err(invalid("truncated DNS query"));
    }
    if u16::from_be_bytes([packet[4], packet[5]]) != 1 {
        return Err(invalid("DNS query must contain exactly one question"));
    }
    let mut cursor = 12;
    let mut labels = Vec::new();
    loop {
        let Some(&length) = packet.get(cursor) else {
            return Err(invalid("truncated DNS name"));
        };
        cursor += 1;
        if length == 0 {
            break;
        }
        if length & 0xc0 != 0 || length > 63 {
            return Err(invalid("compressed/invalid DNS query name"));
        }
        let end = cursor.saturating_add(usize::from(length));
        let label = packet
            .get(cursor..end)
            .ok_or_else(|| invalid("truncated DNS label"))?;
        labels.push(
            std::str::from_utf8(label)
                .map_err(|_| invalid("DNS label is not UTF-8"))?
                .to_owned(),
        );
        cursor = end;
    }
    let question = packet
        .get(cursor..cursor + 4)
        .ok_or_else(|| invalid("truncated DNS question"))?;
    Ok(Query {
        name: labels.join("."),
        query_type: u16::from_be_bytes([question[0], question[1]]),
        question_end: cursor + 4,
    })
}

fn parse_answers(packet: &[u8]) -> std::io::Result<Vec<String>> {
    let header = packet
        .get(..12)
        .ok_or_else(|| invalid("truncated DNS response header"))?;
    let question_count = usize::from(u16::from_be_bytes([header[4], header[5]]));
    let answer_count = usize::from(u16::from_be_bytes([header[6], header[7]]));
    let mut cursor = 12;
    for _ in 0..question_count {
        cursor = skip_name(packet, cursor)?;
        cursor = cursor
            .checked_add(4)
            .filter(|end| *end <= packet.len())
            .ok_or_else(|| invalid("truncated DNS response question"))?;
    }

    let mut answers = Vec::new();
    for _ in 0..answer_count {
        cursor = skip_name(packet, cursor)?;
        let fields = packet
            .get(cursor..cursor + 10)
            .ok_or_else(|| invalid("truncated DNS answer"))?;
        let record_type = u16::from_be_bytes([fields[0], fields[1]]);
        let data_length = usize::from(u16::from_be_bytes([fields[8], fields[9]]));
        cursor += 10;
        let data = packet
            .get(cursor..cursor + data_length)
            .ok_or_else(|| invalid("truncated DNS answer data"))?;
        match (record_type, data) {
            (1, [a, b, c, d]) => {
                answers.push(std::net::Ipv4Addr::new(*a, *b, *c, *d).to_string());
            }
            (28, data) if data.len() == 16 => {
                let octets: [u8; 16] = data
                    .try_into()
                    .map_err(|_| invalid("invalid DNS IPv6 answer"))?;
                answers.push(std::net::Ipv6Addr::from(octets).to_string());
            }
            _ => {}
        }
        cursor += data_length;
    }
    Ok(answers)
}

fn skip_name(packet: &[u8], mut cursor: usize) -> std::io::Result<usize> {
    loop {
        let length = *packet
            .get(cursor)
            .ok_or_else(|| invalid("truncated DNS name"))?;
        if length & 0xc0 == 0xc0 {
            return cursor
                .checked_add(2)
                .filter(|end| *end <= packet.len())
                .ok_or_else(|| invalid("truncated DNS name pointer"));
        }
        if length & 0xc0 != 0 || length > 63 {
            return Err(invalid("invalid DNS name"));
        }
        cursor += 1;
        if length == 0 {
            return Ok(cursor);
        }
        cursor = cursor
            .checked_add(usize::from(length))
            .filter(|end| *end <= packet.len())
            .ok_or_else(|| invalid("truncated DNS name label"))?;
    }
}

fn override_response(
    packet: &[u8],
    query: &Query,
    address: IpAddr,
    ttl: u32,
) -> std::io::Result<Vec<u8>> {
    let mut response = packet
        .get(..query.question_end)
        .ok_or_else(|| invalid("truncated DNS question"))?
        .to_vec();
    response[2] |= 0x80;
    response[3] |= 0x80;
    response[6..8].copy_from_slice(&1_u16.to_be_bytes());
    response[8..12].fill(0);
    response.extend_from_slice(&[0xc0, 0x0c]);
    response.extend_from_slice(&query.query_type.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&ttl.to_be_bytes());
    match address {
        IpAddr::V4(address) => {
            response.extend_from_slice(&4_u16.to_be_bytes());
            response.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            response.extend_from_slice(&16_u16.to_be_bytes());
            response.extend_from_slice(&address.octets());
        }
    }
    Ok(response)
}

fn invalid(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn query(name: &str, query_type: u16) -> Vec<u8> {
        let mut packet = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            packet.push(u8::try_from(label.len()).unwrap());
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&query_type.to_be_bytes());
        packet.extend_from_slice(&1_u16.to_be_bytes());
        packet
    }

    #[test]
    fn parses_query_and_builds_ipv4_and_ipv6_overrides() {
        let packet = query("api.example.test", 1);
        let parsed = parse_query(&packet).unwrap();
        assert_eq!(parsed.name, "api.example.test");
        assert_eq!(parsed.query_type, 1);
        let response = override_response(
            &packet,
            &parsed,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            60,
        )
        .unwrap();
        assert_eq!(&response[6..8], &[0, 1]);
        assert_eq!(&response[response.len() - 4..], &[127, 0, 0, 1]);
        assert_eq!(parse_answers(&response).unwrap(), ["127.0.0.1"]);

        let packet = query("v6.example.test", 28);
        let parsed = parse_query(&packet).unwrap();
        let response =
            override_response(&packet, &parsed, IpAddr::V6(Ipv6Addr::LOCALHOST), 60).unwrap();
        assert_eq!(
            &response[response.len() - 16..],
            &Ipv6Addr::LOCALHOST.octets()
        );
        assert_eq!(parse_answers(&response).unwrap(), ["::1"]);
    }

    #[test]
    fn config_normalizes_override_names() {
        let mut config = DnsConfig::new("1.1.1.1:53".parse().unwrap());
        config.add_override("API.Example.Test.", "127.0.0.1".parse().unwrap());
        assert_eq!(
            config.overrides["api.example.test"],
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        );
    }

    #[tokio::test]
    async fn override_packet_is_returned_and_emits_query_and_response_events() {
        let listener = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut config = DnsConfig::new("127.0.0.1:9".parse().unwrap());
        config.add_override("api.example.test", IpAddr::V4(Ipv4Addr::LOCALHOST));
        let (event_tx, mut event_rx) = mpsc::channel(4);

        handle_packet(
            Arc::clone(&listener),
            client.local_addr().unwrap(),
            query("api.example.test", 1),
            config,
            event_tx,
        )
        .await
        .unwrap();

        let mut response = [0_u8; 512];
        let length = client.recv(&mut response).await.unwrap();
        assert_eq!(parse_answers(&response[..length]).unwrap(), ["127.0.0.1"]);
        let ProxyEvent::DnsQuery { id, name, .. } = event_rx.recv().await.unwrap() else {
            panic!("expected DNS query event");
        };
        assert_eq!(name, "api.example.test");
        let ProxyEvent::DnsResponse {
            id: response_id,
            overridden,
            ..
        } = event_rx.recv().await.unwrap()
        else {
            panic!("expected DNS response event");
        };
        assert_eq!(response_id, id);
        assert!(overridden);
    }

    #[test]
    fn rejects_truncated_and_malformed_dns_packets() {
        assert_eq!(
            parse_query(&[]).err().unwrap().kind(),
            std::io::ErrorKind::InvalidData
        );

        let mut packet = vec![0_u8; 17];
        assert!(parse_query(&packet).is_err());
        packet[5] = 1;
        packet[12] = 0xc0;
        assert!(parse_query(&packet).is_err());
        packet[12] = 64;
        assert!(parse_query(&packet).is_err());

        let mut invalid_utf8 = vec![0_u8; 12];
        invalid_utf8[5] = 1;
        invalid_utf8.extend_from_slice(&[1, 0xff, 0, 0, 1, 0, 1]);
        assert!(parse_query(&invalid_utf8).is_err());

        let mut missing_question = vec![0_u8; 12];
        missing_question[5] = 1;
        missing_question.push(0);
        assert!(parse_query(&missing_question).is_err());

        assert!(parse_answers(&[]).is_err());
        let mut missing_name = vec![0_u8; 12];
        missing_name[5] = 1;
        assert!(parse_answers(&missing_name).is_err());
        let mut invalid_name = vec![0_u8; 12];
        invalid_name[7] = 1;
        invalid_name.push(64);
        assert!(parse_answers(&invalid_name).is_err());
        let mut truncated_pointer = vec![0_u8; 12];
        truncated_pointer[7] = 1;
        truncated_pointer.push(0xc0);
        assert!(parse_answers(&truncated_pointer).is_err());

        let mut missing_fields = vec![0_u8; 12];
        missing_fields[7] = 1;
        missing_fields.push(0);
        assert!(parse_answers(&missing_fields).is_err());

        let mut missing_data = vec![0_u8; 12];
        missing_data[7] = 1;
        missing_data.push(0);
        missing_data.extend_from_slice(&1_u16.to_be_bytes());
        missing_data.extend_from_slice(&1_u16.to_be_bytes());
        missing_data.extend_from_slice(&30_u32.to_be_bytes());
        missing_data.extend_from_slice(&4_u16.to_be_bytes());
        assert!(parse_answers(&missing_data).is_err());

        let mut ignored_record = vec![0_u8; 12];
        ignored_record[7] = 1;
        ignored_record.push(0);
        ignored_record.extend_from_slice(&16_u16.to_be_bytes());
        ignored_record.extend_from_slice(&1_u16.to_be_bytes());
        ignored_record.extend_from_slice(&30_u32.to_be_bytes());
        ignored_record.extend_from_slice(&1_u16.to_be_bytes());
        ignored_record.push(b'x');
        assert!(parse_answers(&ignored_record).unwrap().is_empty());

        let parsed = Query {
            name: "example.test".to_owned(),
            query_type: 1,
            question_end: 100,
        };
        assert!(override_response(
            &query("example.test", 1),
            &parsed,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            30
        )
        .is_err());
    }
}
