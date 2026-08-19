#![forbid(unsafe_code)]

use std::alloc::System;
use std::convert::Infallible;
use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::stream;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt as _, Full, StreamBody};
use hyper::body::Frame;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use openssl::x509::X509;
use proxyapi::ca::{CertificateAuthority, Ssl};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use serde::Serialize;
use stats_alloc::{Region, StatsAlloc, INSTRUMENTED_SYSTEM};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

type BenchBody = BoxBody<Bytes, Infallible>;
type BoxIo = Pin<Box<dyn BenchIo>>;

trait BenchIo: AsyncRead + AsyncWrite + Send {}
impl<T> BenchIo for T where T: AsyncRead + AsyncWrite + Send {}

#[derive(Clone, Copy, Debug)]
enum Protocol {
    Http1,
    Http2,
}

#[derive(Clone, Copy, Debug)]
struct Scenario {
    name: &'static str,
    protocol: Protocol,
    tls: bool,
    concurrency: usize,
    response_chunks: usize,
    complex_headers: bool,
}

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "h1_plain_sequential",
        protocol: Protocol::Http1,
        tls: false,
        concurrency: 1,
        response_chunks: 1,
        complex_headers: false,
    },
    Scenario {
        name: "h1_tls_sequential",
        protocol: Protocol::Http1,
        tls: true,
        concurrency: 1,
        response_chunks: 1,
        complex_headers: false,
    },
    Scenario {
        name: "h1_plain_streaming",
        protocol: Protocol::Http1,
        tls: false,
        concurrency: 1,
        response_chunks: 16,
        complex_headers: false,
    },
    Scenario {
        name: "h1_plain_complex_headers",
        protocol: Protocol::Http1,
        tls: false,
        concurrency: 1,
        response_chunks: 1,
        complex_headers: true,
    },
    Scenario {
        name: "h2_plain_concurrent",
        protocol: Protocol::Http2,
        tls: false,
        concurrency: 32,
        response_chunks: 1,
        complex_headers: false,
    },
    Scenario {
        name: "h2_tls_concurrent",
        protocol: Protocol::Http2,
        tls: true,
        concurrency: 32,
        response_chunks: 1,
        complex_headers: false,
    },
];

#[derive(Debug)]
struct Options {
    iterations: usize,
    warmup: usize,
    output: Option<PathBuf>,
}

#[derive(Serialize)]
struct Baseline {
    schema_version: u32,
    generated_at_unix_ms: u128,
    git_commit: String,
    rustc: String,
    target: String,
    iterations: usize,
    warmup: usize,
    results: Vec<ScenarioResult>,
}

#[derive(Serialize)]
struct ScenarioResult {
    name: &'static str,
    protocol: &'static str,
    tls: bool,
    concurrency: usize,
    response_chunks: usize,
    complex_headers: bool,
    throughput_requests_per_second: f64,
    p50_latency_us: u128,
    p99_latency_us: u128,
    allocations_per_request: f64,
    allocated_bytes_per_request: f64,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let options = parse_options()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let results = runtime.block_on(async {
        let mut results = Vec::with_capacity(SCENARIOS.len());
        for scenario in SCENARIOS {
            let result = run_scenario(*scenario, options.warmup, options.iterations)
                .await
                .unwrap_or_else(|error| panic!("scenario {} failed: {error}", scenario.name));
            eprintln!(
                "{}: {:.0} req/s, p99 {} us, {:.2} alloc/req",
                result.name,
                result.throughput_requests_per_second,
                result.p99_latency_us,
                result.allocations_per_request
            );
            results.push(result);
        }
        results
    });

    let baseline = Baseline {
        schema_version: 1,
        generated_at_unix_ms: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
        git_commit: command_output("git", &["rev-parse", "HEAD"]),
        rustc: command_output("rustc", &["--version"]),
        target: command_output("rustc", &["-vV"])
            .lines()
            .find_map(|line| line.strip_prefix("host: "))
            .unwrap_or("unknown")
            .to_owned(),
        iterations: options.iterations,
        warmup: options.warmup,
        results,
    };
    let json = serde_json::to_string_pretty(&baseline)?;
    if let Some(path) = options.output {
        fs::write(path, format!("{json}\n"))?;
    } else {
        println!("{json}");
    }
    Ok(())
}

fn parse_options() -> Result<Options, io::Error> {
    let mut iterations = 10_000;
    let mut warmup = 1_000;
    let mut output = None;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            // Cargo appends this marker to custom benchmark executables.
            "--bench" => {}
            "--iterations" => iterations = parse_usize(&mut args, "--iterations")?,
            "--warmup" => warmup = parse_usize(&mut args, "--warmup")?,
            "--output" => {
                output = Some(PathBuf::from(args.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--output requires a path")
                })?));
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown argument: {other}"),
                ));
            }
        }
    }
    if iterations == 0 || warmup == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "iterations and warmup must be greater than zero",
        ));
    }
    Ok(Options {
        iterations,
        warmup,
        output,
    })
}

fn parse_usize(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<usize, io::Error> {
    args.next()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{flag} requires a value"),
            )
        })?
        .parse()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))
}

async fn run_scenario(
    scenario: Scenario,
    warmup: usize,
    iterations: usize,
) -> Result<ScenarioResult, Box<dyn std::error::Error>> {
    let (client_io, server_io) = io_pair(scenario.tls, scenario.protocol).await?;
    let server = spawn_server(server_io, scenario);

    let result = match scenario.protocol {
        Protocol::Http1 => run_http1(client_io, scenario, warmup, iterations).await?,
        Protocol::Http2 => run_http2(client_io, scenario, warmup, iterations).await?,
    };

    server.abort();
    Ok(result)
}

fn spawn_server(io: BoxIo, scenario: Scenario) -> tokio::task::JoinHandle<()> {
    let service = service_fn(move |request| serve(request, scenario));
    match scenario.protocol {
        Protocol::Http1 => tokio::spawn(async move {
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(io), service)
                .await;
        }),
        Protocol::Http2 => tokio::spawn(async move {
            let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(io), service)
                .await;
        }),
    }
}

async fn serve(
    request: Request<hyper::body::Incoming>,
    scenario: Scenario,
) -> Result<Response<BenchBody>, Infallible> {
    let _ = request.into_body().collect().await;
    let chunks = (0..scenario.response_chunks).map(|_| {
        Ok::<_, Infallible>(Frame::data(Bytes::from_static(
            b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )))
    });
    let body = StreamBody::new(stream::iter(chunks)).boxed();
    let mut response = Response::new(body);
    if scenario.complex_headers {
        for index in 0..24 {
            response.headers_mut().append(
                http::header::SET_COOKIE,
                format!("session-{index}=value-{index}; Path=/")
                    .parse()
                    .expect("static benchmark header is valid"),
            );
        }
    }
    Ok(response)
}

async fn run_http1(
    io: BoxIo,
    scenario: Scenario,
    warmup: usize,
    iterations: usize,
) -> Result<ScenarioResult, Box<dyn std::error::Error>> {
    let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
        .handshake(TokioIo::new(io))
        .await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    for _ in 0..warmup {
        execute_one(&mut sender, scenario).await?;
    }

    let region = Region::new(GLOBAL);
    let started = Instant::now();
    let mut latencies = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let request_started = Instant::now();
        execute_one(&mut sender, scenario).await?;
        latencies.push(request_started.elapsed());
    }
    let elapsed = started.elapsed();
    let stats = region.change();
    Ok(result_from_stats(
        scenario,
        iterations,
        elapsed,
        latencies,
        stats.allocations,
        stats.bytes_allocated,
    ))
}

async fn execute_one(
    sender: &mut hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    scenario: Scenario,
) -> Result<(), Box<dyn std::error::Error>> {
    sender.ready().await?;
    let response = sender.send_request(request(scenario)?).await?;
    response.into_body().collect().await?;
    Ok(())
}

async fn run_http2(
    io: BoxIo,
    scenario: Scenario,
    warmup: usize,
    iterations: usize,
) -> Result<ScenarioResult, Box<dyn std::error::Error>> {
    let (mut sender, connection) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
        .handshake(TokioIo::new(io))
        .await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    run_http2_batches(&mut sender, scenario, warmup, None).await?;

    let region = Region::new(GLOBAL);
    let started = Instant::now();
    let mut latencies = Vec::with_capacity(iterations);
    run_http2_batches(&mut sender, scenario, iterations, Some(&mut latencies)).await?;
    let elapsed = started.elapsed();
    let stats = region.change();
    Ok(result_from_stats(
        scenario,
        iterations,
        elapsed,
        latencies,
        stats.allocations,
        stats.bytes_allocated,
    ))
}

async fn run_http2_batches(
    sender: &mut hyper::client::conn::http2::SendRequest<Full<Bytes>>,
    scenario: Scenario,
    count: usize,
    mut latencies: Option<&mut Vec<Duration>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut completed = 0;
    while completed < count {
        let batch_size = scenario.concurrency.min(count - completed);
        let started = Instant::now();
        let mut pending = Vec::with_capacity(batch_size);
        for _ in 0..batch_size {
            sender.ready().await?;
            pending.push(sender.send_request(request(scenario)?));
        }
        for response in futures_util::future::try_join_all(pending).await? {
            response.into_body().collect().await?;
        }
        if let Some(samples) = latencies.as_deref_mut() {
            let latency = started.elapsed();
            samples.extend(std::iter::repeat_n(latency, batch_size));
        }
        completed += batch_size;
    }
    Ok(())
}

fn request(scenario: Scenario) -> Result<Request<Full<Bytes>>, http::Error> {
    let mut request = Request::builder()
        .method("POST")
        .uri("https://benchmark.invalid/resource?query=value")
        .header("content-type", "application/octet-stream")
        .body(Full::new(Bytes::from_static(b"benchmark request body")))?;
    if scenario.complex_headers {
        for index in 0..24 {
            request.headers_mut().append(
                http::header::COOKIE,
                format!("cookie-{index}=value-{index}")
                    .parse()
                    .expect("static benchmark header is valid"),
            );
        }
    }
    Ok(request)
}

fn result_from_stats(
    scenario: Scenario,
    iterations: usize,
    elapsed: Duration,
    mut latencies: Vec<Duration>,
    allocations: usize,
    bytes_allocated: usize,
) -> ScenarioResult {
    latencies.sort_unstable();
    let p50 = percentile(&latencies, 50);
    let p99 = percentile(&latencies, 99);
    ScenarioResult {
        name: scenario.name,
        protocol: match scenario.protocol {
            Protocol::Http1 => "http1",
            Protocol::Http2 => "http2",
        },
        tls: scenario.tls,
        concurrency: scenario.concurrency,
        response_chunks: scenario.response_chunks,
        complex_headers: scenario.complex_headers,
        throughput_requests_per_second: iterations as f64 / elapsed.as_secs_f64(),
        p50_latency_us: p50.as_micros(),
        p99_latency_us: p99.as_micros(),
        allocations_per_request: allocations as f64 / iterations as f64,
        allocated_bytes_per_request: bytes_allocated as f64 / iterations as f64,
    }
}

fn percentile(samples: &[Duration], percentile: usize) -> Duration {
    let index = samples.len().saturating_sub(1).saturating_mul(percentile) / 100;
    samples[index]
}

async fn io_pair(
    tls: bool,
    protocol: Protocol,
) -> Result<(BoxIo, BoxIo), Box<dyn std::error::Error>> {
    let (client, server) = tokio::io::duplex(1024 * 1024);
    if !tls {
        return Ok((Box::pin(client), Box::pin(server)));
    }

    tls_pair(client, server, protocol).await
}

async fn tls_pair(
    client: DuplexStream,
    server: DuplexStream,
    protocol: Protocol,
) -> Result<(BoxIo, BoxIo), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let authority = "benchmark.invalid:443".parse()?;
    let ca = Ssl::load_or_generate(directory.path())?;
    let mut server_config = (*ca.gen_server_config(&authority).await?).clone();
    let alpn = match protocol {
        Protocol::Http1 => b"http/1.1".as_slice(),
        Protocol::Http2 => b"h2".as_slice(),
    };
    server_config.alpn_protocols = vec![alpn.to_vec()];

    let certificate = X509::from_pem(&ca.ca_cert_pem())?;
    let mut roots = RootCertStore::empty();
    roots.add(certificate.to_der()?.into())?;
    let mut client_config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![alpn.to_vec()];

    let accept = TlsAcceptor::from(Arc::new(server_config)).accept(server);
    let connect = TlsConnector::from(Arc::new(client_config)).connect(
        ServerName::try_from("benchmark.invalid")?.to_owned(),
        client,
    );
    let (client, server) = tokio::try_join!(connect, accept)?;
    Ok((Box::pin(client), Box::pin(server)))
}

fn command_output(program: &str, args: &[&str]) -> String {
    std::process::Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_else(|| "unknown".to_owned())
}
