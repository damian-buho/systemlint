// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! The requests a `network: true` collector makes: TCP connects, DNS queries and HTTP GETs, each retried with backoff.

use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use systemlint_protocol::{Input, ProbeInput, ProbeKind, VERSION};

use crate::collector::{Body, Http, Read as Sources};
use crate::runner::OUTPUT_CAP;

/// How many times a request is tried before its error is kept.
pub const ATTEMPTS: u32 = 3;

/// The wait before the second attempt, doubled before each later one.
pub const BACKOFF: Duration = Duration::from_millis(500);

/// The resolver configuration a `dns` probe without `dns-server` reads, on the host running systemlint.
pub const RESOLV_CONF: &str = "/etc/resolv.conf";

/// The headers whose value is replaced with `[redacted]`, since it carries a secret.
const REDACTED_HEADERS: &[&str] = &["set-cookie"];

/// How a request reaches the network, read from the environment once per run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Proxies {
    pub http: Option<String>,
    pub https: Option<String>,
    pub no_proxy: Vec<String>,
}

impl Proxies {
    /// `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` from `var`, the lowercase name first as curl reads them.
    pub fn from_env(var: impl Fn(&str) -> Option<String>) -> Self {
        let either = |name: &str| {
            var(&name.to_ascii_lowercase())
                .or_else(|| var(name))
                .filter(|v| !v.trim().is_empty())
        };
        Self {
            http: either("HTTP_PROXY"),
            https: either("HTTPS_PROXY"),
            no_proxy: either("NO_PROXY")
                .unwrap_or_default()
                .split(',')
                .map(|h| h.trim().trim_start_matches('.').to_ascii_lowercase())
                .filter(|h| !h.is_empty())
                .collect(),
        }
    }

    /// The proxy URL a request to `host` over `scheme` goes through, `None` when direct.
    pub fn route(&self, scheme: &str, host: &str) -> Option<&str> {
        let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
        let bypass = self
            .no_proxy
            .iter()
            .any(|entry| entry == "*" || host == *entry || host.ends_with(&format!(".{entry}")));
        let proxy = match scheme {
            "https" => self.https.as_deref(),
            _ => self.http.as_deref(),
        };
        log::trace!("route {scheme}://{host}: proxy {proxy:?}, bypass {bypass}");
        proxy.filter(|_| !bypass)
    }
}

/// How the requests of one run are made.
#[derive(Debug, Clone)]
pub struct Settings {
    pub timeout: Duration,
    pub now: SystemTime,
    pub proxies: Proxies,
}

/// Why one attempt failed: worth another try, or final.
#[derive(Debug)]
pub enum Failure {
    Retry(String),
    Final(String),
}

/// The wait before attempt `attempt + 1`: [`BACKOFF`] doubled per earlier attempt, scaled by `1 + jitter` for `jitter` in 0 to 1.
pub fn backoff(attempt: u32, jitter: f64) -> Duration {
    BACKOFF
        .saturating_mul(1 << attempt.saturating_sub(1).min(16))
        .mul_f64(1.0 + jitter.clamp(0.0, 1.0))
}

/// A random fraction in 0 to 1, or 0 when the kernel gives no randomness.
fn jitter() -> f64 {
    let mut bytes = [0u8; 4];
    match rustix::rand::getrandom(&mut bytes, rustix::rand::GetRandomFlags::empty()) {
        Ok(4) => f64::from(u32::from_ne_bytes(bytes)) / f64::from(u32::MAX),
        other => {
            log::debug!("no jitter, getrandom answered {other:?}");
            0.0
        }
    }
}

/// Runs `once` up to [`ATTEMPTS`] times, waiting [`backoff`] between, logging each attempt and its time.
pub fn retry<T>(what: &str, mut once: impl FnMut() -> Result<T, Failure>) -> Result<T, String> {
    let mut attempt = 1;
    loop {
        let started = Instant::now();
        log::debug!("{what}: attempt {attempt} of {ATTEMPTS}");
        let failure = match once() {
            Ok(value) => {
                log::debug!("{what}: answered in {} ms", started.elapsed().as_millis());
                return Ok(value);
            }
            Err(failure) => failure,
        };
        let ms = started.elapsed().as_millis();
        match failure {
            Failure::Final(reason) => {
                log::debug!("{what}: {reason} after {ms} ms, final");
                return Err(reason);
            }
            Failure::Retry(reason) if attempt >= ATTEMPTS => {
                log::debug!("{what}: {reason} after {ms} ms, attempt {attempt} was the last");
                return Err(format!("{reason}, {ATTEMPTS} times"));
            }
            Failure::Retry(reason) => {
                let wait = backoff(attempt, jitter());
                log::debug!(
                    "{what}: {reason} after {ms} ms, retrying in {} ms",
                    wait.as_millis()
                );
                std::thread::sleep(wait);
                attempt += 1;
            }
        }
    }
}

/// Every probe `read` lists, in its order: addr, then dns, then http.
pub fn probes(read: &Sources, settings: &Settings) -> Vec<Input> {
    let addr = read.addr.iter().map(|t| addr(t, settings));
    let dns = read.dns.iter().map(|n| dns(n, read, settings));
    let http = read.http.iter().map(|h| http(h, settings));
    addr.chain(dns).chain(http).map(Input::Probe).collect()
}

/// A probe input from what one target answered.
fn input(probe: ProbeKind, target: &str, answer: Result<Map<String, Value>, String>) -> ProbeInput {
    match answer {
        Ok(facts) => kept(probe, target, facts, None),
        Err(error) => kept(probe, target, Map::new(), Some(error)),
    }
}

/// A probe input of `facts`, with the `error` that left the others out.
fn kept(
    probe: ProbeKind,
    target: &str,
    facts: Map<String, Value>,
    error: Option<String>,
) -> ProbeInput {
    log::debug!(
        "{} {target}: {} facts, error {error:?}",
        probe.key(),
        facts.len()
    );
    ProbeInput {
        probe,
        target: target.to_owned(),
        facts,
        error,
    }
}

/// `host:port` split, the host unbracketed, refusing a port outside 1 to 65535.
pub fn split_addr(target: &str) -> Result<(String, u16), String> {
    let (host, port) = target.rsplit_once(':').ok_or("is not host:port")?;
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if host.is_empty() || host.contains(['/', ' ']) {
        return Err(format!("host {host:?} is not a hostname or address"));
    }
    match port.parse::<u16>() {
        Ok(port) if port > 0 => Ok((host.to_owned(), port)),
        _ => Err(format!("port {port:?} is not 1 to 65535")),
    }
}

/// The addresses `host` resolves to, each with `port`.
fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>, Failure> {
    let found: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| Failure::Retry(format!("can’t resolve {host}: {e}")))?
        .collect();
    log::trace!("{host} resolves to {found:?}");
    match found.is_empty() {
        true => Err(Failure::Retry(format!("{host} resolves to no address"))),
        false => Ok(found),
    }
}

/// Whether a TCP connection to `target` opens: `reachable`, false once every address refused or timed out; unresolvable is an error.
pub fn addr(target: &str, settings: &Settings) -> ProbeInput {
    let mut resolved = false;
    let answer = split_addr(target).and_then(|(host, port)| {
        retry(&format!("connect {target}"), || {
            let addresses = resolve(&host, port)?;
            resolved = true;
            let mut last = None;
            for address in &addresses {
                match TcpStream::connect_timeout(address, settings.timeout) {
                    Ok(_) => {
                        log::debug!("connect {target}: {address} accepted");
                        return Ok(true);
                    }
                    Err(e) => {
                        log::debug!("connect {target}: {address} answered {e}");
                        last = Some(e);
                    }
                }
            }
            match last {
                Some(e) if refused(&e) => Ok(false),
                Some(e) => Err(Failure::Retry(e.to_string())),
                None => Ok(false),
            }
        })
    });
    let answer = match answer {
        Err(reason) if resolved => {
            log::debug!("connect {target}: unreachable, {reason}");
            Ok(false)
        }
        other => other,
    };
    input(
        ProbeKind::Addr,
        target,
        answer.map(|reachable| Map::from_iter([("reachable".to_owned(), Value::Bool(reachable))])),
    )
}

/// Whether `error` is a definite no from the network, not worth another try.
fn refused(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::HostUnreachable
            | io::ErrorKind::NetworkUnreachable
    )
}

/// `server` as a socket address, port 53 when it names only an IP.
pub fn dns_server(server: &str) -> Result<SocketAddr, String> {
    server
        .parse::<SocketAddr>()
        .or_else(|_| server.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, 53)))
        .map_err(|_| "is not an IP address, nor one with :port".to_owned())
}

/// The `nameserver` lines of `text`, a resolv.conf, in order.
pub fn nameservers(text: &str) -> Vec<SocketAddr> {
    text.lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .filter_map(|rest| rest.split_whitespace().next())
        .filter_map(|ip| dns_server(ip.split('%').next().unwrap_or(ip)).ok())
        .collect()
}

/// The servers a `dns` probe asks, in order.
fn servers(read: &Sources) -> Result<Vec<SocketAddr>, String> {
    if let Some(server) = &read.dns_server {
        return dns_server(server).map(|s| vec![s]);
    }
    let text = std::fs::read_to_string(RESOLV_CONF)
        .map_err(|e| format!("can’t read {RESOLV_CONF}: {e}"))?;
    let found = nameservers(&text);
    log::debug!("{RESOLV_CONF} names {} nameservers", found.len());
    match found.is_empty() {
        true => Err(format!("{RESOLV_CONF} names no nameserver")),
        false => Ok(found),
    }
}

/// The records `name` holds for each of `read.dns-types`, sorted, and `resolvable` when any came back; a server that gave no answer is an error.
pub fn dns(name: &str, read: &Sources, settings: &Settings) -> ProbeInput {
    let answer = servers(read).and_then(|servers| {
        let mut facts = Map::new();
        let mut any = false;
        for kind in &read.dns_types {
            let records = retry(&format!("dns {kind} {name}"), || {
                query(name, kind, &servers, settings.timeout)
            })?;
            any |= !records.is_empty();
            facts.insert(kind.clone(), json!(records));
        }
        facts.insert("resolvable".to_owned(), Value::Bool(any));
        Ok(facts)
    });
    input(ProbeKind::Dns, name, answer)
}

/// One query of `kind` for `name`, each server in turn until one answers: the record data, empty for NXDOMAIN.
fn query(
    name: &str,
    kind: &str,
    servers: &[SocketAddr],
    timeout: Duration,
) -> Result<Vec<String>, Failure> {
    let rtype: RecordType = kind
        .parse()
        .map_err(|e| Failure::Final(format!("record type {kind}: {e}")))?;
    let fqdn = match name.ends_with('.') {
        true => name.to_owned(),
        false => format!("{name}."),
    };
    let qname = Name::from_ascii(&fqdn).map_err(|e| Failure::Final(format!("{name}: {e}")))?;
    let mut bytes = [0u8; 2];
    let _ = rustix::rand::getrandom(&mut bytes, rustix::rand::GetRandomFlags::empty());
    let id = u16::from_ne_bytes(bytes);
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(qname.clone(), rtype));
    let request = message
        .to_vec()
        .map_err(|e| Failure::Final(format!("can’t encode the query: {e}")))?;
    let mut last = String::new();
    for server in servers {
        match exchange(&request, *server, timeout).and_then(|reply| {
            Message::from_vec(&reply).map_err(|e| format!("answered no DNS message: {e}"))
        }) {
            Ok(reply) if reply.metadata.id != id => {
                last = format!("{server} answered query {} for {id}", reply.metadata.id);
            }
            Ok(reply) => {
                let code = reply.metadata.response_code;
                log::debug!(
                    "dns {kind} {name}: {server} answered {code}, {} records",
                    reply.answers.len()
                );
                return match code {
                    ResponseCode::NoError => {
                        let mut records: Vec<String> = reply
                            .answers
                            .iter()
                            .filter(|r| r.record_type() == rtype)
                            .map(|r| r.data.to_string())
                            .collect();
                        records.sort();
                        records.dedup();
                        Ok(records)
                    }
                    ResponseCode::NXDomain => Ok(Vec::new()),
                    other => Err(Failure::Retry(format!("{server} answered {other}"))),
                };
            }
            Err(e) => last = format!("{server} {e}"),
        }
        log::debug!("dns {kind} {name}: {last}");
    }
    Err(Failure::Retry(last))
}

/// The reply to `request` from `server` over UDP, again over TCP when it came back truncated.
fn exchange(request: &[u8], server: SocketAddr, timeout: Duration) -> Result<Vec<u8>, String> {
    let bind: SocketAddr = match server {
        SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap_or_else(|_| unreachable!()),
        SocketAddr::V6(_) => "[::]:0".parse().unwrap_or_else(|_| unreachable!()),
    };
    let udp = UdpSocket::bind(bind).map_err(|e| format!("can’t open a UDP socket: {e}"))?;
    udp.set_read_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    udp.connect(server)
        .map_err(|e| format!("can’t reach: {e}"))?;
    udp.send(request).map_err(|e| format!("can’t send: {e}"))?;
    let mut reply = vec![0u8; 65535];
    let n = udp
        .recv(&mut reply)
        .map_err(|e| format!("gave no answer: {e}"))?;
    reply.truncate(n);
    let truncated = reply.get(2).is_some_and(|flags| flags & 0x02 != 0);
    if !truncated {
        return Ok(reply);
    }
    log::debug!("dns {server}: UDP answer truncated, asking over TCP");
    let mut tcp = TcpStream::connect_timeout(&server, timeout).map_err(|e| format!("TCP: {e}"))?;
    tcp.set_read_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    tcp.set_write_timeout(Some(timeout))
        .map_err(|e| e.to_string())?;
    let length = u16::try_from(request.len()).map_err(|_| "query over 64 KiB".to_owned())?;
    tcp.write_all(&[&length.to_be_bytes()[..], request].concat())
        .map_err(|e| format!("TCP: {e}"))?;
    let mut size = [0u8; 2];
    tcp.read_exact(&mut size).map_err(|e| format!("TCP: {e}"))?;
    let mut reply = vec![0u8; usize::from(u16::from_be_bytes(size))];
    tcp.read_exact(&mut reply)
        .map_err(|e| format!("TCP: {e}"))?;
    Ok(reply)
}

/// The response to one GET of `probe.url`, never following a redirect: `status`, `headers`, `body-sha256`, `json` when asked, and `tls`.
pub fn http(probe: &Http, settings: &Settings) -> ProbeInput {
    let (facts, error) = retry(&format!("GET {}", probe.url), || get(probe, settings))
        .unwrap_or_else(|error| (Map::new(), Some(error)));
    kept(ProbeKind::Http, &probe.url, facts, error)
}

/// A byte stream a request is written to and its response read from.
trait Conn: Read + Write {}
impl<T: Read + Write> Conn for T {}

/// One attempt of [`http`]: the facts, and the error that left some out.
fn get(probe: &Http, settings: &Settings) -> Result<(Map<String, Value>, Option<String>), Failure> {
    let url = url::Url::parse(&probe.url).map_err(|e| Failure::Final(e.to_string()))?;
    let https = url.scheme() == "https";
    let host = url.host_str().unwrap_or_default().to_owned();
    let port = url
        .port_or_known_default()
        .unwrap_or(if https { 443 } else { 80 });
    let proxy = match settings.proxies.route(url.scheme(), &host) {
        Some(proxy) => Some(proxy_address(proxy)?),
        None => None,
    };
    let (dial_host, dial_port) = proxy.clone().unwrap_or((host.clone(), port));
    log::debug!("GET {}: connecting to {dial_host}:{dial_port}", probe.url);
    let mut tcp = connect(&dial_host, dial_port, settings.timeout)?;
    let mut facts = Map::new();
    let deadline = Instant::now() + settings.timeout;
    let target = match (&proxy, https) {
        (Some(_), false) => url.as_str().to_owned(),
        _ => url[url::Position::BeforePath..url::Position::AfterQuery].to_owned(),
    };
    let authorization = match (&probe.username, &probe.password_file) {
        (Some(user), Some(file)) => {
            let password = std::fs::read_to_string(file)
                .map_err(|e| Failure::Final(format!("can’t read {}: {e}", file.display())))?;
            let password = password.trim_end_matches(['\n', '\r']);
            Some(crate::collect::base64(
                format!("{user}:{password}").as_bytes(),
            ))
        }
        _ => None,
    };
    let mut tls;
    let conn: &mut dyn Conn = if https {
        if proxy.is_some() {
            tunnel(&mut tcp, &host, port, deadline)?;
        }
        let verifier = Arc::new(Recorder::new(probe)?);
        let config = ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .map_err(|e| Failure::Final(format!("TLS: {e}")))?
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();
        let name = ServerName::try_from(host.clone())
            .map_err(|e| Failure::Final(format!("TLS server name {host}: {e}")))?;
        let mut client = ClientConnection::new(Arc::new(config), name)
            .map_err(|e| Failure::Final(format!("TLS: {e}")))?;
        while client.is_handshaking() {
            client
                .complete_io(&mut tcp)
                .map_err(|e| Failure::Retry(format!("TLS handshake: {e}")))?;
        }
        let checked = verifier
            .outcome
            .lock()
            .map(|o| o.clone())
            .unwrap_or_default();
        facts.insert(
            "tls".to_owned(),
            tls_facts(&client, checked.as_ref(), settings.now),
        );
        log::debug!(
            "GET {}: TLS {:?}, verified {checked:?}",
            probe.url,
            client.protocol_version()
        );
        if let Some(Err(reason)) = checked {
            return Ok((
                facts,
                Some(format!("TLS not trusted, nothing sent: {reason}")),
            ));
        }
        tls = rustls::StreamOwned::new(client, tcp);
        &mut tls
    } else {
        &mut tcp
    };
    let mut request = format!(
        "GET {target} HTTP/1.1\r\nHost: {}\r\nUser-Agent: systemlint/{VERSION}\r\nAccept: */*\r\nConnection: close\r\n",
        &url[url::Position::BeforeHost..url::Position::AfterPort]
    );
    if let Some(credentials) = &authorization {
        request.push_str(&format!("Authorization: Basic {credentials}\r\n"));
    }
    request.push_str("\r\n");
    conn.write_all(request.as_bytes())
        .and_then(|()| conn.flush())
        .map_err(|e| Failure::Retry(format!("can’t send the request: {e}")))?;
    let (raw, clean) = read_all(conn, deadline)?;
    let response = parse(&raw, clean)?;
    log::debug!(
        "GET {}: {} with {} body bytes",
        probe.url,
        response.status,
        response.body.len()
    );
    if response.status >= 500 {
        log::debug!(
            "GET {}: server error {} kept as a fact",
            probe.url,
            response.status
        );
    }
    facts.insert("status".to_owned(), Value::from(response.status));
    facts.insert("headers".to_owned(), Value::Object(response.headers));
    let digest: String = Sha256::digest(&response.body)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    facts.insert("body-sha256".to_owned(), Value::from(digest));
    let mut error = None;
    if probe.body == Some(Body::Json) {
        match serde_json::from_slice::<Value>(&response.body) {
            Ok(json) => drop(facts.insert("json".to_owned(), json)),
            Err(e) => error = Some(format!("body is not JSON: {e}")),
        }
    }
    Ok((facts, error))
}

/// A TCP connection to `host:port`, trying each address it resolves to.
fn connect(host: &str, port: u16, timeout: Duration) -> Result<TcpStream, Failure> {
    let mut last = String::new();
    for address in resolve(host, port)? {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(tcp) => {
                tcp.set_read_timeout(Some(timeout))
                    .and_then(|()| tcp.set_write_timeout(Some(timeout)))
                    .map_err(|e| Failure::Retry(e.to_string()))?;
                return Ok(tcp);
            }
            Err(e) => {
                log::debug!("connect {host}:{port}: {address} answered {e}");
                last = format!("can’t connect to {address}: {e}");
            }
        }
    }
    Err(Failure::Retry(last))
}

/// The host and port of an `http://` proxy URL; any other scheme, or credentials in it, is refused.
fn proxy_address(proxy: &str) -> Result<(String, u16), Failure> {
    let url = url::Url::parse(proxy).map_err(|e| Failure::Final(format!("proxy {proxy}: {e}")))?;
    if url.scheme() != "http" {
        return Err(Failure::Final(format!(
            "proxy scheme {} is not supported, only http://",
            url.scheme()
        )));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Failure::Final(
            "a proxy with credentials is not supported".to_owned(),
        ));
    }
    let host = url
        .host_str()
        .unwrap_or_default()
        .trim_matches(['[', ']'])
        .to_owned();
    Ok((host, url.port_or_known_default().unwrap_or(80)))
}

/// Opens a CONNECT tunnel to `host:port` through the proxy on `tcp`.
fn tunnel(tcp: &mut TcpStream, host: &str, port: u16, deadline: Instant) -> Result<(), Failure> {
    let authority = match host.contains(':') {
        true => format!("[{host}]:{port}"),
        false => format!("{host}:{port}"),
    };
    tcp.write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .map_err(|e| Failure::Retry(format!("proxy: {e}")))?;
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 16 * 1024 || Instant::now() > deadline {
            return Err(Failure::Retry(
                "proxy sent no whole CONNECT answer".to_owned(),
            ));
        }
        match tcp.read(&mut byte) {
            Ok(0) => return Err(Failure::Retry("proxy closed the CONNECT".to_owned())),
            Ok(_) => head.push(byte[0]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(Failure::Retry(format!("proxy: {e}"))),
        }
    }
    let line = String::from_utf8_lossy(&head);
    let code = line.split_whitespace().nth(1).unwrap_or_default();
    log::debug!("CONNECT {authority}: proxy answered {code}");
    match code.starts_with('2') {
        true => Ok(()),
        false => Err(Failure::Final(format!(
            "proxy refused CONNECT {authority} with {code}"
        ))),
    }
}

/// Everything `conn` sends until it closes, and whether it closed cleanly, failing past [`OUTPUT_CAP`] or `deadline`.
fn read_all(conn: &mut dyn Conn, deadline: Instant) -> Result<(Vec<u8>, bool), Failure> {
    let (mut raw, mut chunk) = (Vec::new(), vec![0u8; 16 * 1024]);
    loop {
        if Instant::now() > deadline {
            return Err(Failure::Retry(
                "sent no whole answer within the timeout".to_owned(),
            ));
        }
        match conn.read(&mut chunk) {
            Ok(0) => return Ok((raw, true)),
            Ok(n) if (raw.len() + n) as u64 > OUTPUT_CAP => {
                return Err(Failure::Final(format!(
                    "answer over {} MiB",
                    OUTPUT_CAP >> 20
                )));
            }
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok((raw, false)),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(Failure::Retry(format!("answer cut short: {e}"))),
        }
    }
}

/// An HTTP response: its status, headers and decoded body.
#[derive(Debug, PartialEq)]
pub struct Response {
    pub status: u16,
    pub headers: Map<String, Value>,
    pub body: Vec<u8>,
}

/// `raw` as an HTTP/1.1 response; a body cut short of its framing, or one ended by an unclean close, is retried.
pub fn parse(raw: &[u8], clean: bool) -> Result<Response, Failure> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| Failure::Retry("answer ends before its headers do".to_owned()))?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.strip_prefix("HTTP/1."))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| Failure::Final("answered no HTTP/1 status line".to_owned()))?;
    let mut headers = Map::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            log::debug!("header line {line:?} has no colon, skipped");
            continue;
        };
        let (name, value) = (name.trim().to_ascii_lowercase(), value.trim());
        let value = match REDACTED_HEADERS.contains(&name.as_str()) {
            true => crate::collect::REDACTED,
            false => value,
        };
        match headers.get_mut(&name) {
            Some(Value::String(joined)) => *joined = format!("{joined}, {value}"),
            _ => drop(headers.insert(name, Value::from(value))),
        }
    }
    let rest = &raw[split + 4..];
    let header = |name: &str| {
        headers
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_ascii_lowercase)
    };
    let body = if header("transfer-encoding").is_some_and(|t| t.contains("chunked")) {
        dechunk(rest)?
    } else if let Some(length) = header("content-length") {
        let length: usize = length
            .parse()
            .map_err(|_| Failure::Final(format!("content-length {length:?} is not a number")))?;
        rest.get(..length)
            .ok_or_else(|| {
                Failure::Retry(format!(
                    "body cut short at {} of {length} bytes",
                    rest.len()
                ))
            })?
            .to_vec()
    } else if clean || status == 204 || status == 304 {
        rest.to_vec()
    } else {
        return Err(Failure::Retry(
            "body ended by a connection cut, not a close".to_owned(),
        ));
    };
    Ok(Response {
        status,
        headers,
        body,
    })
}

/// A chunked body decoded, failing when it ends before its last chunk.
fn dechunk(mut rest: &[u8]) -> Result<Vec<u8>, Failure> {
    let short = || Failure::Retry("chunked body cut short".to_owned());
    let mut body = Vec::new();
    loop {
        let end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(short)?;
        let size = String::from_utf8_lossy(&rest[..end]);
        let size = usize::from_str_radix(size.split(';').next().unwrap_or_default().trim(), 16)
            .map_err(|_| Failure::Final(format!("chunk size {size:?} is not hexadecimal")))?;
        rest = &rest[end + 2..];
        if size == 0 {
            return Ok(body);
        }
        body.extend_from_slice(rest.get(..size).ok_or_else(short)?);
        rest = rest.get(size + 2..).ok_or_else(short)?;
    }
}

/// The `tls` facts of a finished handshake: `verified`, `error`, `version` and the leaf certificate’s dates, `days-left`, `percent-left`, issuer and subject.
fn tls_facts(
    client: &ClientConnection,
    checked: Option<&Result<(), String>>,
    now: SystemTime,
) -> Value {
    let mut tls = Map::new();
    tls.insert(
        "verified".to_owned(),
        Value::Bool(matches!(checked, Some(Ok(())))),
    );
    if let Some(Err(reason)) = checked {
        tls.insert("error".to_owned(), Value::from(reason.as_str()));
    }
    if let Some(version) = client.protocol_version() {
        let name = format!("{version:?}")
            .replace("TLSv1_", "1.")
            .replace("TLSv", "");
        tls.insert("version".to_owned(), Value::from(name));
    }
    let leaf = client.peer_certificates().and_then(|chain| chain.first());
    match leaf.map(|der| x509_parser::parse_x509_certificate(der)) {
        Some(Ok((_, cert))) => {
            let validity = cert.validity();
            let (before, after) = (
                validity.not_before.timestamp(),
                validity.not_after.timestamp(),
            );
            let at = |seconds: i64| {
                crate::collect::rfc3339(
                    UNIX_EPOCH + Duration::from_secs(seconds.max(0).unsigned_abs()),
                )
            };
            let now = now
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_secs() as i64);
            tls.insert("not-before".to_owned(), Value::from(at(before)));
            tls.insert("not-after".to_owned(), Value::from(at(after)));
            tls.insert(
                "days-left".to_owned(),
                Value::from((after - now).div_euclid(86_400)),
            );
            // Whole percent of the validity period still ahead, absent for an empty period.
            if after > before {
                let percent =
                    (i128::from(after - now) * 100).div_euclid(i128::from(after - before));
                log::debug!("leaf certificate has {percent}% of its validity left");
                tls.insert("percent-left".to_owned(), Value::from(percent as i64));
            }
            tls.insert("issuer".to_owned(), Value::from(cert.issuer().to_string()));
            tls.insert(
                "subject".to_owned(),
                Value::from(cert.subject().to_string()),
            );
        }
        Some(Err(e)) => log::debug!("leaf certificate does not parse: {e}"),
        None => log::debug!("server sent no certificate"),
    }
    Value::Object(tls)
}

/// The crypto every TLS probe uses.
fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// The CA certificates this host trusts, loaded once per run.
fn native_roots() -> &'static Result<Arc<RootCertStore>, String> {
    static ROOTS: OnceLock<Result<Arc<RootCertStore>, String>> = OnceLock::new();
    ROOTS.get_or_init(|| {
        let found = rustls_native_certs::load_native_certs();
        log::debug!(
            "{} native CA certificates, {} errors",
            found.certs.len(),
            found.errors.len()
        );
        let mut store = RootCertStore::empty();
        let (added, ignored) = store.add_parsable_certificates(found.certs);
        log::debug!("trusting {added} CA certificates, {ignored} unparsable");
        match store.is_empty() {
            true => Err("this host trusts no CA certificate".to_owned()),
            false => Ok(Arc::new(store)),
        }
    })
}

/// A verifier that lets the handshake finish, so the certificate is read, and records whether the host would trust it.
#[derive(Debug)]
struct Recorder {
    inner: Result<Arc<WebPkiServerVerifier>, String>,
    algorithms: WebPkiSupportedAlgorithms,
    outcome: Mutex<Option<Result<(), String>>>,
}

impl Recorder {
    /// A recorder trusting `probe.ca-file` alone when set, else this host’s CA certificates.
    fn new(probe: &Http) -> Result<Self, Failure> {
        let roots = match &probe.ca_file {
            Some(file) => {
                let pem = std::fs::read(file)
                    .map_err(|e| Failure::Final(format!("can’t read {}: {e}", file.display())))?;
                let mut store = RootCertStore::empty();
                let certs = CertificateDer::pem_slice_iter(&pem).filter_map(Result::ok);
                let (added, ignored) = store.add_parsable_certificates(certs);
                log::debug!(
                    "{}: {added} CA certificates, {ignored} unparsable",
                    file.display()
                );
                match store.is_empty() {
                    true => Err(format!("{} holds no CA certificate", file.display())),
                    false => Ok(Arc::new(store)),
                }
            }
            None => native_roots().clone(),
        };
        let provider = provider();
        let inner = roots.and_then(|roots| {
            WebPkiServerVerifier::builder_with_provider(roots, provider.clone())
                .build()
                .map_err(|e| e.to_string())
        });
        Ok(Self {
            inner,
            algorithms: provider.signature_verification_algorithms,
            outcome: Mutex::new(None),
        })
    }
}

impl ServerCertVerifier for Recorder {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let checked = match &self.inner {
            Ok(inner) => inner
                .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
                .map(|_| ())
                .map_err(|e| e.to_string()),
            Err(reason) => Err(reason.clone()),
        };
        log::debug!("certificate for {server_name:?}: {checked:?}");
        if let Ok(mut outcome) = self.outcome.lock() {
            *outcome = Some(checked);
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}
