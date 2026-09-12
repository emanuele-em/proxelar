#![forbid(unsafe_code)]

use std::alloc::System;
use std::env;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::{future, stream};
use proxelar_proto::{
    BoxFuture, HttpService, ProtocolError, ProxyBody, ProxyRequest, ProxyResponse, RequestHead,
    ResponseHead,
};
use proxyapi::ca::{CertificateAuthority, Ssl};
use proxyapi_models::HeaderBlock;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::pem::PemObject as _;
use rustls_pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use stats_alloc::{Region, StatsAlloc, INSTRUMENTED_SYSTEM};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

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
    baseline: Option<PathBuf>,
    comparison: Option<PathBuf>,
    scenario: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct BenchmarkRun {
    schema_version: u32,
    generated_at_unix_ms: u128,
    git_commit: String,
    rustc: String,
    target: String,
    iterations: usize,
    warmup: usize,
    results: Vec<ScenarioResult>,
}

#[derive(Clone, Deserialize, Serialize)]
struct ScenarioResult {
    name: String,
    protocol: String,
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

#[derive(Serialize)]
struct Comparison {
    schema_version: u32,
    baseline_git_commit: String,
    final_git_commit: String,
    baseline_path: String,
    final_path: String,
    thresholds: Thresholds,
    passed: bool,
    results: Vec<ComparisonResult>,
}

#[derive(Serialize)]
struct Thresholds {
    minimum_throughput_ratio: f64,
    maximum_p99_ratio: f64,
    maximum_allocations_ratio: f64,
}

#[derive(Serialize)]
struct ComparisonResult {
    name: String,
    baseline_throughput_requests_per_second: f64,
    final_throughput_requests_per_second: f64,
    throughput_ratio: f64,
    baseline_p99_latency_us: u128,
    final_p99_latency_us: u128,
    p99_ratio: f64,
    baseline_allocations_per_request: f64,
    final_allocations_per_request: f64,
    allocations_ratio: f64,
    baseline_allocated_bytes_per_request: f64,
    final_allocated_bytes_per_request: f64,
    allocated_bytes_ratio: f64,
    throughput_passed: bool,
    p99_passed: bool,
    allocations_passed: bool,
    passed: bool,
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
            if options
                .scenario
                .as_deref()
                .is_some_and(|selected| selected != scenario.name)
            {
                continue;
            }
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

    let run = BenchmarkRun {
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
    let json = serde_json::to_string_pretty(&run)?;
    if let Some(path) = &options.output {
        fs::write(path, format!("{json}\n"))?;
    } else {
        println!("{json}");
    }

    if let (Some(baseline_path), Some(comparison_path)) = (&options.baseline, &options.comparison) {
        let baseline: BenchmarkRun = serde_json::from_slice(&fs::read(baseline_path)?)?;
        let comparison = compare_runs(&baseline, &run, baseline_path, options.output.as_deref())?;
        fs::write(
            comparison_path,
            format!("{}\n", serde_json::to_string_pretty(&comparison)?),
        )?;
        if !comparison.passed {
            return Err(io::Error::other(format!(
                "protocol performance gate failed; inspect {}",
                comparison_path.display()
            ))
            .into());
        }
    }
    Ok(())
}

fn parse_options() -> Result<Options, io::Error> {
    let mut iterations = 10_000;
    let mut warmup = 1_000;
    let mut output = None;
    let mut baseline = None;
    let mut comparison = None;
    let mut scenario = None;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bench" => {}
            "--iterations" => iterations = parse_usize(&mut args, "--iterations")?,
            "--warmup" => warmup = parse_usize(&mut args, "--warmup")?,
            "--output" => output = Some(parse_path(&mut args, "--output")?),
            "--baseline" => baseline = Some(parse_path(&mut args, "--baseline")?),
            "--comparison" => comparison = Some(parse_path(&mut args, "--comparison")?),
            "--scenario" => {
                scenario = Some(args.next().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--scenario requires a scenario name",
                    )
                })?)
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
    if baseline.is_some() != comparison.is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--baseline and --comparison must be provided together",
        ));
    }
    if let Some(selected) = &scenario {
        if !SCENARIOS.iter().any(|candidate| candidate.name == selected) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown scenario: {selected}"),
            ));
        }
    }
    Ok(Options {
        iterations,
        warmup,
        output,
        baseline,
        comparison,
        scenario,
    })
}

fn parse_path(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<PathBuf, io::Error> {
    args.next().map(PathBuf::from).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{flag} requires a path"),
        )
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
    let service = BenchService { scenario };
    match scenario.protocol {
        Protocol::Http1 => tokio::spawn(async move {
            let _ = proxelar_proto::http1::serve_connection(
                io,
                service,
                proxelar_proto::http1::ConnectionConfig::default(),
            )
            .await;
        }),
        Protocol::Http2 => tokio::spawn(async move {
            let _ = proxelar_proto::http2::serve_connection(
                io,
                service,
                proxelar_proto::http2::ConnectionConfig::default(),
            )
            .await;
        }),
    }
}

#[derive(Clone, Copy)]
struct BenchService {
    scenario: Scenario,
}

impl HttpService for BenchService {
    fn call(
        &mut self,
        request: ProxyRequest,
    ) -> BoxFuture<'_, Result<ProxyResponse, ProtocolError>> {
        let scenario = self.scenario;
        Box::pin(async move {
            request.body.collect().await?;
            let mut headers = HeaderBlock::new();
            if scenario.complex_headers {
                for index in 0..24 {
                    headers
                        .add(
                            "set-cookie",
                            format!("session-{index}=value-{index}; Path=/"),
                        )
                        .expect("static benchmark header is valid");
                }
            }
            let chunks = (0..scenario.response_chunks).map(|_| {
                Ok(proxelar_proto::BodyFrame::Data(Bytes::from_static(
                    b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                )))
            });
            let body = ProxyBody::new(stream::iter(chunks)).with_trailer_hint(false);
            let version = match scenario.protocol {
                Protocol::Http1 => http::Version::HTTP_11,
                Protocol::Http2 => http::Version::HTTP_2,
            };
            Ok(ProxyResponse::new(
                ResponseHead::new(http::StatusCode::OK, version, headers),
                body,
            ))
        })
    }
}

async fn run_http1(
    io: BoxIo,
    scenario: Scenario,
    warmup: usize,
    iterations: usize,
) -> Result<ScenarioResult, Box<dyn std::error::Error>> {
    let client = proxelar_proto::http1::Http1Client::new(
        io,
        proxelar_proto::http1::ConnectionConfig::default(),
    );
    for _ in 0..warmup {
        execute_http1(&client, scenario).await?;
    }

    let region = Region::new(GLOBAL);
    let started = Instant::now();
    let mut latencies = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let request_started = Instant::now();
        execute_http1(&client, scenario).await?;
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

async fn execute_http1(
    client: &proxelar_proto::http1::Http1Client,
    scenario: Scenario,
) -> Result<(), Box<dyn std::error::Error>> {
    client
        .send_request(request(scenario)?)
        .await?
        .body
        .collect()
        .await?;
    Ok(())
}

async fn run_http2(
    io: BoxIo,
    scenario: Scenario,
    warmup: usize,
    iterations: usize,
) -> Result<ScenarioResult, Box<dyn std::error::Error>> {
    let client = proxelar_proto::http2::H2Client::handshake(
        io,
        proxelar_proto::http2::ConnectionConfig::default(),
    )
    .await?;
    run_http2_batches(&client, scenario, warmup, None).await?;

    let region = Region::new(GLOBAL);
    let started = Instant::now();
    let mut latencies = Vec::with_capacity(iterations);
    run_http2_batches(&client, scenario, iterations, Some(&mut latencies)).await?;
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
    client: &proxelar_proto::http2::H2Client,
    scenario: Scenario,
    count: usize,
    mut latencies: Option<&mut Vec<Duration>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut completed = 0;
    while completed < count {
        let batch_size = scenario.concurrency.min(count - completed);
        let started = Instant::now();
        let pending = (0..batch_size).map(|_| client.send_request(request(scenario).unwrap()));
        for response in future::try_join_all(pending).await? {
            response.body.collect().await?;
        }
        if let Some(samples) = latencies.as_deref_mut() {
            let latency = started.elapsed();
            samples.extend(std::iter::repeat_n(latency, batch_size));
        }
        completed += batch_size;
    }
    Ok(())
}

fn request(scenario: Scenario) -> Result<ProxyRequest, Box<dyn std::error::Error>> {
    let (uri, version) = match scenario.protocol {
        Protocol::Http1 => ("/resource?query=value".parse()?, http::Version::HTTP_11),
        Protocol::Http2 => (
            "https://benchmark.invalid/resource?query=value".parse()?,
            http::Version::HTTP_2,
        ),
    };
    let mut headers = HeaderBlock::new();
    if matches!(scenario.protocol, Protocol::Http1) {
        headers.add("host", "benchmark.invalid")?;
    }
    headers.add("content-type", "application/octet-stream")?;
    if scenario.complex_headers {
        for index in 0..24 {
            headers.add("cookie", format!("cookie-{index}=value-{index}"))?;
        }
    }
    Ok(ProxyRequest::new(
        RequestHead::new(http::Method::POST, uri, version, headers),
        ProxyBody::full(Bytes::from_static(b"benchmark request body")),
    ))
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
    ScenarioResult {
        name: scenario.name.to_owned(),
        protocol: match scenario.protocol {
            Protocol::Http1 => "http1",
            Protocol::Http2 => "http2",
        }
        .to_owned(),
        tls: scenario.tls,
        concurrency: scenario.concurrency,
        response_chunks: scenario.response_chunks,
        complex_headers: scenario.complex_headers,
        throughput_requests_per_second: iterations as f64 / elapsed.as_secs_f64(),
        p50_latency_us: percentile(&latencies, 50).as_micros(),
        p99_latency_us: percentile(&latencies, 99).as_micros(),
        allocations_per_request: allocations as f64 / iterations as f64,
        allocated_bytes_per_request: bytes_allocated as f64 / iterations as f64,
    }
}

fn percentile(samples: &[Duration], percentile: usize) -> Duration {
    let index = samples.len().saturating_sub(1).saturating_mul(percentile) / 100;
    samples[index]
}

fn compare_runs(
    baseline: &BenchmarkRun,
    final_run: &BenchmarkRun,
    baseline_path: &Path,
    final_path: Option<&Path>,
) -> Result<Comparison, io::Error> {
    if baseline.schema_version != final_run.schema_version
        || baseline.target != final_run.target
        || baseline.iterations != final_run.iterations
        || baseline.warmup != final_run.warmup
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "baseline and final benchmark configuration do not match",
        ));
    }
    let mut results = Vec::with_capacity(baseline.results.len());
    for baseline_result in &baseline.results {
        let final_result = final_run
            .results
            .iter()
            .find(|result| result.name == baseline_result.name)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("final benchmark is missing {}", baseline_result.name),
                )
            })?;
        if baseline_result.protocol != final_result.protocol
            || baseline_result.tls != final_result.tls
            || baseline_result.concurrency != final_result.concurrency
            || baseline_result.response_chunks != final_result.response_chunks
            || baseline_result.complex_headers != final_result.complex_headers
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "baseline and final scenario configuration differ for {}",
                    baseline_result.name
                ),
            ));
        }
        let throughput_ratio = ratio(
            final_result.throughput_requests_per_second,
            baseline_result.throughput_requests_per_second,
        );
        let p99_ratio = ratio(
            final_result.p99_latency_us as f64,
            baseline_result.p99_latency_us as f64,
        );
        let allocations_ratio = ratio(
            final_result.allocations_per_request,
            baseline_result.allocations_per_request,
        );
        let allocated_bytes_ratio = ratio(
            final_result.allocated_bytes_per_request,
            baseline_result.allocated_bytes_per_request,
        );
        let throughput_passed = throughput_ratio >= 1.0;
        let p99_passed = p99_ratio <= 1.05;
        let allocations_passed = allocations_ratio <= 1.0;
        results.push(ComparisonResult {
            name: baseline_result.name.clone(),
            baseline_throughput_requests_per_second: baseline_result.throughput_requests_per_second,
            final_throughput_requests_per_second: final_result.throughput_requests_per_second,
            throughput_ratio,
            baseline_p99_latency_us: baseline_result.p99_latency_us,
            final_p99_latency_us: final_result.p99_latency_us,
            p99_ratio,
            baseline_allocations_per_request: baseline_result.allocations_per_request,
            final_allocations_per_request: final_result.allocations_per_request,
            allocations_ratio,
            baseline_allocated_bytes_per_request: baseline_result.allocated_bytes_per_request,
            final_allocated_bytes_per_request: final_result.allocated_bytes_per_request,
            allocated_bytes_ratio,
            throughput_passed,
            p99_passed,
            allocations_passed,
            passed: throughput_passed && p99_passed && allocations_passed,
        });
    }
    if results.len() != final_run.results.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "baseline and final benchmark scenario counts do not match",
        ));
    }
    Ok(Comparison {
        schema_version: 1,
        baseline_git_commit: baseline.git_commit.clone(),
        final_git_commit: final_run.git_commit.clone(),
        baseline_path: recorded_path(baseline_path),
        final_path: final_path.map_or_else(|| "stdout".to_owned(), recorded_path),
        thresholds: Thresholds {
            minimum_throughput_ratio: 1.0,
            maximum_p99_ratio: 1.05,
            maximum_allocations_ratio: 1.0,
        },
        passed: results.iter().all(|result| result.passed),
        results,
    })
}

fn recorded_path(path: &Path) -> String {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("proxyapi is a workspace member");
    path.strip_prefix(workspace)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn ratio(numerator: f64, denominator: f64) -> f64 {
    if denominator == 0.0 {
        if numerator == 0.0 {
            1.0
        } else {
            f64::INFINITY
        }
    } else {
        numerator / denominator
    }
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

    let certificate = CertificateDer::from_pem_slice(&ca.ca_cert_pem())?;
    let mut roots = RootCertStore::empty();
    roots.add(certificate)?;
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
