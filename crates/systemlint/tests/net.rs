// SPDX-FileCopyrightText: 2026 Damián Búho <damian.buho@proton.me>
//
// SPDX-License-Identifier: AGPL-3.0-only

//! Network probes against servers on the loopback: addr, dns, http and https, with retries, proxies and the gate.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, UNIX_EPOCH};

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record, RecordType};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use systemlint::collect::{self, HashKey, Options};
use systemlint::collector::{Collector, Http};
use systemlint::net::{self, Failure, Proxies, Settings};
use systemlint::source::Root;
use systemlint_protocol::ProbeInput;

/// 2030-01-01T00:00:00Z, the test leaf certificate’s not-after.
const NOT_AFTER: u64 = 1_893_456_000;
/// Seconds from the test leaf’s `not_before`, 2026-01-01, to [`NOT_AFTER`].
const LIFETIME: u64 = 1_461 * 86_400;

fn settings(now: u64) -> Settings {
    Settings {
        timeout: Duration::from_secs(30),
        now: UNIX_EPOCH + Duration::from_secs(now),
        proxies: Proxies::default(),
    }
}

fn facts(probe: &ProbeInput) -> Value {
    Value::Object(probe.facts.clone())
}

fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("net");
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

#[test]
fn backoff_doubles_from_half_a_second_and_jitter_adds_at_most_as_much_again() {
    assert_eq!(net::backoff(1, 0.0), Duration::from_millis(500));
    assert_eq!(net::backoff(2, 0.0), Duration::from_secs(1));
    assert_eq!(net::backoff(3, 1.0), Duration::from_secs(4));
    assert_eq!(net::backoff(1, 7.0), Duration::from_secs(1));
    assert_eq!(net::backoff(1, -1.0), Duration::from_millis(500));
}

#[test]
fn retry_stops_on_a_final_failure_and_gives_up_after_three_attempts() {
    let mut calls = 0;
    let final_ = net::retry::<()>("final", || {
        calls += 1;
        Err(Failure::Final("no".to_owned()))
    });
    assert_eq!((final_, calls), (Err("no".to_owned()), 1));
    let mut calls = 0;
    let second = net::retry("second", || {
        calls += 1;
        match calls {
            1 => Err(Failure::Retry("busy".to_owned())),
            n => Ok(n),
        }
    });
    assert_eq!(second, Ok(2));
    let mut calls = 0;
    let never = net::retry::<()>("never", || {
        calls += 1;
        Err(Failure::Retry("busy".to_owned()))
    });
    assert_eq!(
        (never, calls),
        (Err("busy, 3 times".to_owned()), net::ATTEMPTS)
    );
}

#[test]
fn proxies_prefer_the_lowercase_variable_and_no_proxy_bypasses_a_domain_and_its_subdomains() {
    let env = |name: &str| match name {
        "https_proxy" => Some("http://lower:3128".to_owned()),
        "HTTPS_PROXY" => Some("http://upper:3128".to_owned()),
        "HTTP_PROXY" => Some("http://plain:3128".to_owned()),
        "NO_PROXY" => Some(" .internal.test, localhost ,".to_owned()),
        _ => None,
    };
    let proxies = Proxies::from_env(env);
    assert_eq!(proxies.https.as_deref(), Some("http://lower:3128"));
    assert_eq!(proxies.no_proxy, ["internal.test", "localhost"]);
    assert_eq!(
        proxies.route("https", "kiota.ch"),
        Some("http://lower:3128")
    );
    assert_eq!(proxies.route("http", "kiota.ch"), Some("http://plain:3128"));
    assert_eq!(proxies.route("https", "internal.test"), None);
    assert_eq!(proxies.route("https", "a.internal.test"), None);
    assert_eq!(
        proxies.route("https", "notinternal.test"),
        Some("http://lower:3128")
    );
    let all = Proxies::from_env(|n| (n == "NO_PROXY").then(|| "*".to_owned()));
    assert_eq!(all.route("https", "kiota.ch"), None);
}

#[test]
fn an_addr_target_is_host_and_a_port_from_1_to_65535() {
    assert_eq!(
        net::split_addr("kiota.ch:1"),
        Ok(("kiota.ch".to_owned(), 1))
    );
    assert_eq!(
        net::split_addr("[::1]:65535"),
        Ok(("::1".to_owned(), 65535))
    );
    assert!(net::split_addr("kiota.ch:0").is_err());
    assert!(net::split_addr("kiota.ch:65536").is_err());
    assert!(net::split_addr("kiota.ch").is_err());
    assert!(net::split_addr(":443").is_err());
}

#[test]
fn nameservers_are_read_in_order_with_a_zone_index_dropped() {
    let text = "# x\nsearch lan\nnameserver 127.0.0.53\nnameserver fe80::1%eth0\nnameserver nonsense\noptions edns0\n";
    assert_eq!(
        net::nameservers(text),
        [
            "127.0.0.53:53".parse::<SocketAddr>().unwrap(),
            "[fe80::1]:53".parse().unwrap()
        ]
    );
    assert_eq!(
        net::dns_server("192.0.2.1:5353"),
        Ok("192.0.2.1:5353".parse().unwrap())
    );
    assert!(net::dns_server("dns.test").is_err());
}

#[test]
fn an_open_port_is_reachable_and_a_closed_one_is_not() {
    let open = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = format!("127.0.0.1:{}", open.local_addr().unwrap().port());
    assert_eq!(
        facts(&net::addr(&target, &settings(0))),
        json!({"reachable": true})
    );
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = format!("127.0.0.1:{}", closed.local_addr().unwrap().port());
    drop(closed);
    let probe = net::addr(&target, &settings(0));
    assert_eq!(
        (facts(&probe), probe.error),
        (json!({"reachable": false}), None)
    );
}

/// A DNS server on the loopback answering `probe.test.` A with 192.0.2.1, NXDOMAIN for any other name.
fn dns_server() -> SocketAddr {
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = udp.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buffer = [0u8; 512];
        while let Ok((n, peer)) = udp.recv_from(&mut buffer) {
            let query = Message::from_vec(&buffer[..n]).unwrap();
            let question = query.queries[0].clone();
            let mut reply = Message::response(query.metadata.id, query.metadata.op_code);
            reply.add_query(question.clone());
            if question.name().to_ascii() != "probe.test." {
                reply.metadata.response_code = ResponseCode::NXDomain;
            } else if question.query_type() == RecordType::A {
                reply.add_answer(Record::from_rdata(
                    question.name().clone(),
                    60,
                    RData::A(A::new(192, 0, 2, 1)),
                ));
            }
            udp.send_to(&reply.to_vec().unwrap(), peer).unwrap();
        }
    });
    address
}

#[test]
fn dns_lists_each_asked_type_and_a_missing_name_is_not_resolvable() {
    let read = Collector::parse(&format!(
        "id: d\nnetwork: true\nread: {{dns: [probe.test], dns-types: [A, AAAA], dns-server: \"{}\"}}\nparse: {{plugin: formats, op: probes}}\ninto: probes\n",
        dns_server()
    ))
    .unwrap()
    .read;
    let found = net::dns("probe.test", &read, &settings(0));
    assert_eq!(
        (facts(&found), found.error),
        (
            json!({"A": ["192.0.2.1"], "AAAA": [], "resolvable": true}),
            None
        )
    );
    let missing = net::dns("absent.test", &read, &settings(0));
    assert_eq!(
        facts(&missing),
        json!({"A": [], "AAAA": [], "resolvable": false})
    );
}

/// A DNS server on the loopback answering every query with `code` and no record.
fn coded_dns_server(code: ResponseCode) -> SocketAddr {
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = udp.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buffer = [0u8; 512];
        while let Ok((n, peer)) = udp.recv_from(&mut buffer) {
            let query = Message::from_vec(&buffer[..n]).unwrap();
            let mut reply = Message::response(query.metadata.id, query.metadata.op_code);
            reply.add_query(query.queries[0].clone());
            reply.metadata.response_code = code;
            udp.send_to(&reply.to_vec().unwrap(), peer).unwrap();
        }
    });
    address
}

/// A loopback UDP port nothing listens on, so a query to it is refused by the kernel.
fn closed_udp_port() -> SocketAddr {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

#[test]
fn a_nameserver_answers_with_its_codes_or_is_silent_and_a_bad_address_is_an_error() {
    let read = Collector::parse(
        "id: d\nnetwork: true\nread: {dns: [probe.test, absent.test], dns-types: [A], dns-server-from: [resolv.conf.*.nameserver.:3]}\nparse: {plugin: formats, op: probes}\ninto: resolv.probes\n",
    )
    .unwrap()
    .read;
    let ask = |server: String| {
        let probe = net::nameserver(&server, &read, &settings(0));
        (facts(&probe), probe.error)
    };
    assert_eq!(
        ask(dns_server().to_string()),
        (
            json!({"answered": true, "codes": ["NOERROR", "NXDOMAIN"]}),
            None
        )
    );
    assert_eq!(
        ask(coded_dns_server(ResponseCode::Refused).to_string()),
        (json!({"answered": true, "codes": ["REFUSED"]}), None)
    );
    assert_eq!(
        ask(closed_udp_port().to_string()),
        (json!({"answered": false}), None)
    );
    let (bad, error) = ask("dns.test".to_owned());
    assert_eq!(bad, json!({}));
    assert!(error.unwrap().contains("not an IP address"));
}

#[test]
fn dns_server_from_asks_each_named_server_instead_of_the_names() {
    let read = Collector::parse(
        "id: d\nnetwork: true\nread: {dns: [probe.test], dns-server-from: [resolv.conf.*.nameserver.:3]}\nparse: {plugin: formats, op: probes}\ninto: resolv.probes\n",
    )
    .unwrap()
    .read;
    let server = dns_server().to_string();
    let inputs = net::probes(&read, std::slice::from_ref(&server), &settings(0));
    let targets: Vec<_> = inputs
        .iter()
        .map(|i| match i {
            systemlint_protocol::Input::Probe(p) => (p.probe.key(), p.target.clone()),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(targets, [("nameserver", server)]);
}

#[test]
fn named_servers_count_only_ip_addresses_and_their_absent_fact_names_its_collector() {
    let probe = Collector::parse(
        "id: ns\nnetwork: true\nread: {dns: [\".\"], dns-server-from: [resolv.conf.*.nameserver.:3]}\nparse: {plugin: formats, op: probes}\ninto: resolv.probes\n",
    )
    .unwrap();
    let conf = Collector::parse(
        "id: rc\nread: {files: [/etc/resolv.conf]}\nparse: {plugin: formats, op: words}\ninto: resolv.conf\n",
    )
    .unwrap();
    let collectors = [conf, probe.clone()];
    let facts = json!({"resolv": {"conf": {"/etc/resolv.conf": {"nameserver": ["127.0.0.53", "dns.test", "fe80::1%eth0", "192.0.2.1", "192.0.2.2"]}}}});
    let named = collect::named(
        &probe,
        &collectors,
        facts.as_object().unwrap(),
        &Default::default(),
    )
    .unwrap();
    assert_eq!(
        named.servers,
        ["127.0.0.53", "fe80::1%eth0", "192.0.2.1"],
        "glibc asks the first 3 IP addresses, a name skipped before it counts"
    );
    let second = Collector::parse(
        "id: ns\nnetwork: true\nread: {dns: [\".\"], dns-server-from: [resolv.conf.*.nameserver.1]}\nparse: {plugin: formats, op: probes}\ninto: resolv.probes\n",
    )
    .unwrap();
    let one = collect::named(
        &second,
        &collectors,
        facts.as_object().unwrap(),
        &Default::default(),
    )
    .unwrap();
    assert_eq!(
        one.servers,
        [] as [&str; 0],
        "an index takes one item, here a name"
    );
    let outcomes = json!({"rc": {"status": "error"}});
    let missing = collect::named(
        &probe,
        &collectors,
        &Default::default(),
        outcomes.as_object().unwrap(),
    )
    .unwrap_err();
    assert_eq!(
        missing,
        "needs fact resolv.conf, and collector rc finished error"
    );
}

/// Serves one connection: hands what it read up to the blank line to `sent`, then writes `response`.
fn serve<S: Read + Write>(mut stream: S, response: &[u8], sent: &mpsc::Sender<String>) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => break,
        }
    }
    sent.send(String::from_utf8_lossy(&head).into_owned())
        .unwrap();
    if head.ends_with(b"\r\n\r\n") {
        let _ = stream.write_all(response).and_then(|()| stream.flush());
    }
}

/// A plain HTTP server answering every connection with `response`, sending each request head it read.
fn http_server(response: &'static [u8]) -> (SocketAddr, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (sent, heads) = mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            serve(stream, response, &sent);
        }
    });
    (address, heads)
}

#[test]
fn an_http_get_keeps_status_joined_headers_and_the_body_digest_never_a_cookie() {
    let (address, heads) = http_server(
        b"HTTP/1.1 301 Moved\r\nContent-Length: 5\r\nLocation: /next\r\nSet-Cookie: session=secret\r\nX-A: 1\r\nx-a: 2\r\n\r\nhello",
    );
    let url = format!("http://{address}/path?q=1");
    let probe = net::http(
        &Http {
            url,
            ..Http::default()
        },
        &settings(0),
    );
    let digest: String = Sha256::digest(b"hello")
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(probe.error, None);
    assert_eq!(
        facts(&probe),
        json!({"status": 301, "body-sha256": digest, "headers": {
            "content-length": "5", "location": "/next", "set-cookie": "[redacted]", "x-a": "1, 2"
        }})
    );
    let head = heads.recv().unwrap();
    assert!(head.starts_with("GET /path?q=1 HTTP/1.1\r\n"), "{head}");
    assert!(head.contains(&format!("\r\nHost: {address}\r\n")), "{head}");
    assert!(!head.contains("Authorization"), "{head}");
}

#[test]
fn an_http_url_goes_through_the_proxy_in_absolute_form_unless_no_proxy_names_it() {
    let (proxy, heads) = http_server(b"HTTP/1.1 204 No Content\r\n\r\n");
    let url = "http://origin.test:8080/x".to_owned();
    let mut via = settings(0);
    via.proxies = Proxies::from_env(|n| (n == "HTTP_PROXY").then(|| format!("http://{proxy}")));
    let probe = net::http(
        &Http {
            url: url.clone(),
            ..Http::default()
        },
        &via,
    );
    assert_eq!(facts(&probe)["status"], 204);
    assert!(
        heads
            .recv()
            .unwrap()
            .starts_with("GET http://origin.test:8080/x HTTP/1.1\r\n")
    );
    via.proxies.no_proxy = vec!["origin.test".to_owned()];
    let direct = net::http(
        &Http {
            url,
            ..Http::default()
        },
        &via,
    );
    assert!(direct.error.unwrap().contains("origin.test"));
}

#[test]
fn a_proxy_with_credentials_or_another_scheme_is_refused_without_a_request() {
    for proxy in ["http://user:pass@127.0.0.1:1", "socks5h://127.0.0.1:9050"] {
        let mut via = settings(0);
        via.proxies = Proxies::from_env(|n| (n == "HTTPS_PROXY").then(|| proxy.to_owned()));
        let url = "https://kiota.ch/".to_owned();
        let probe = net::http(
            &Http {
                url,
                ..Http::default()
            },
            &via,
        );
        assert!(probe.facts.is_empty() && probe.error.is_some(), "{proxy}");
    }
}

#[test]
fn a_response_body_follows_its_framing_and_a_cut_one_is_retried() {
    let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;x=y\r\nhel\r\n2\r\nlo\r\n0\r\n\r\n";
    assert_eq!(
        net::parse(chunked, false).ok().map(|r| r.body),
        Some(b"hello".to_vec())
    );
    let cut = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel";
    assert!(matches!(net::parse(cut, true), Err(Failure::Retry(_))));
    let short = b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nhello";
    assert!(matches!(net::parse(short, true), Err(Failure::Retry(_))));
    let exact = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    assert_eq!(
        net::parse(exact, false).ok().map(|r| r.body),
        Some(b"hello".to_vec())
    );
    let closed = b"HTTP/1.1 200 OK\r\n\r\nhello";
    assert!(net::parse(closed, true).is_ok());
    assert!(matches!(net::parse(closed, false), Err(Failure::Retry(_))));
    assert!(matches!(
        net::parse(b"SSH-2.0\r\n\r\n", true),
        Err(Failure::Final(_))
    ));
}

/// A test CA, written to a PEM file, and a `localhost` leaf it signed, valid until [`NOT_AFTER`].
struct Pki {
    ca_file: PathBuf,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

fn pki(name: &str) -> Pki {
    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.distinguished_name
        .push(DnType::CommonName, "systemlint test CA");
    let ca_cert = ca.self_signed(&ca_key).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    leaf.distinguished_name
        .push(DnType::CommonName, "localhost");
    leaf.not_before = rcgen::date_time_ymd(2026, 1, 1);
    leaf.not_after = rcgen::date_time_ymd(2030, 1, 1);
    let leaf_cert = leaf.signed_by(&leaf_key, &Issuer::new(ca, ca_key)).unwrap();
    let ca_file = scratch(&format!("{name}-ca.pem"));
    std::fs::write(&ca_file, ca_cert.pem()).unwrap();
    Pki {
        ca_file,
        chain: vec![leaf_cert.der().clone(), ca_cert.der().clone()],
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
    }
}

/// An HTTPS server for `localhost` answering every connection with `response`, sending each request head it read.
fn https_server(pki: &Pki, response: &'static [u8]) -> (u16, mpsc::Receiver<String>) {
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(pki.chain.clone(), pki.key.clone_key())
    .unwrap();
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (sent, heads) = mpsc::channel();
    std::thread::spawn(move || {
        for tcp in listener.incoming().flatten() {
            let tls = rustls::ServerConnection::new(config.clone()).unwrap();
            let mut stream = rustls::StreamOwned::new(tls, tcp);
            serve(&mut stream, response, &sent);
            stream.conn.send_close_notify();
            let _ = stream.flush();
        }
    });
    (port, heads)
}

#[test]
fn https_with_its_ca_file_is_verified_and_counts_days_and_percent_left_to_the_second() {
    let pki = pki("verified");
    let (port, heads) = https_server(&pki, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
    let probe = Http {
        url: format!("https://localhost:{port}/"),
        ca_file: Some(pki.ca_file.clone()),
        ..Http::default()
    };
    let ten_days = net::http(&probe, &settings(NOT_AFTER - 10 * 86_400));
    assert_eq!(ten_days.error, None);
    let tls = &facts(&ten_days)["tls"];
    assert_eq!(
        (
            &tls["verified"],
            &tls["version"],
            &tls["days-left"],
            &tls["not-after"]
        ),
        (
            &json!(true),
            &json!("1.3"),
            &json!(10),
            &json!("2030-01-01T00:00:00Z")
        )
    );
    assert_eq!(tls["issuer"], "CN=systemlint test CA");
    assert_eq!(tls["subject"], "CN=localhost");
    assert_eq!(facts(&ten_days)["status"], 200);
    assert!(heads.recv().unwrap().starts_with("GET / HTTP/1.1\r\n"));
    let inside = net::http(&probe, &settings(NOT_AFTER - 10 * 86_400 + 1));
    assert_eq!(facts(&inside)["tls"]["days-left"], 9);
    let expired = net::http(&probe, &settings(NOT_AFTER + 1));
    assert_eq!(facts(&expired)["tls"]["days-left"], -1);
    assert_eq!(facts(&expired)["tls"]["percent-left"], -1);
    let tenth = net::http(&probe, &settings(NOT_AFTER - LIFETIME / 10));
    assert_eq!(facts(&tenth)["tls"]["percent-left"], 10);
    let under = net::http(&probe, &settings(NOT_AFTER - LIFETIME / 10 + 1));
    assert_eq!(facts(&under)["tls"]["percent-left"], 9);
}

#[test]
fn an_untrusted_certificate_is_described_and_nothing_is_sent() {
    let pki = pki("untrusted");
    let other = self::pki("other");
    let (port, heads) = https_server(&pki, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let probe = Http {
        url: format!("https://localhost:{port}/"),
        username: Some("user".to_owned()),
        password_file: Some(other.ca_file.clone()),
        ca_file: Some(other.ca_file),
        ..Http::default()
    };
    let refused = net::http(&probe, &settings(NOT_AFTER - 86_400));
    let found = facts(&refused);
    assert_eq!(found["tls"]["verified"], false);
    assert_eq!(found["tls"]["days-left"], 1);
    assert!(found.get("status").is_none(), "{found}");
    assert!(
        refused
            .error
            .unwrap()
            .starts_with("TLS not trusted, nothing sent")
    );
    assert_eq!(heads.recv().unwrap(), "");
}

#[test]
fn credentials_from_a_password_file_go_only_over_verified_tls() {
    let pki = pki("credentials");
    let (port, heads) = https_server(&pki, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let password = scratch("password");
    std::fs::write(&password, "s3cret\n").unwrap();
    let probe = Http {
        url: format!("https://localhost:{port}/"),
        username: Some("user".to_owned()),
        password_file: Some(password),
        ca_file: Some(pki.ca_file.clone()),
        ..Http::default()
    };
    assert_eq!(facts(&net::http(&probe, &settings(0)))["status"], 200);
    let expected = collect::base64(b"user:s3cret");
    assert!(
        heads
            .recv()
            .unwrap()
            .contains(&format!("\r\nAuthorization: Basic {expected}\r\n"))
    );
}

#[test]
fn https_goes_through_a_connect_tunnel_and_reads_a_json_body() {
    let pki = pki("tunnel");
    let (port, _heads) = https_server(
        &pki,
        b"HTTP/1.1 200 OK\r\nContent-Length: 21\r\n\r\n{\"eol\": \"2028-04-30\"}",
    );
    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = proxy.local_addr().unwrap();
    let (asked, connects) = mpsc::channel();
    std::thread::spawn(move || {
        let (mut client, _) = proxy.accept().unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") && client.read(&mut byte).unwrap() == 1 {
            head.push(byte[0]);
        }
        asked
            .send(String::from_utf8_lossy(&head).into_owned())
            .unwrap();
        let mut origin = TcpStream::connect(("127.0.0.1", port)).unwrap();
        client
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .unwrap();
        let (mut up, mut down) = (client.try_clone().unwrap(), origin.try_clone().unwrap());
        std::thread::spawn(move || std::io::copy(&mut up, &mut down));
        let _ = std::io::copy(&mut origin, &mut client);
    });
    let mut via = settings(0);
    via.proxies = Proxies::from_env(|n| (n == "HTTPS_PROXY").then(|| format!("http://{address}")));
    let probe = Http {
        url: format!("https://localhost:{port}/api"),
        ca_file: Some(pki.ca_file.clone()),
        body: Some(systemlint::collector::Body::Json),
        ..Http::default()
    };
    let answer = net::http(&probe, &via);
    assert_eq!(answer.error, None);
    assert_eq!(facts(&answer)["json"], json!({"eol": "2028-04-30"}));
    assert!(
        connects
            .recv()
            .unwrap()
            .starts_with(&format!("CONNECT localhost:{port} HTTP/1.1\r\n"))
    );
}

fn options(live: bool, network: bool) -> Options {
    Options {
        privileged: true,
        root: Root::open(Path::new("/")).unwrap(),
        live,
        now: UNIX_EPOCH,
        timeout: Duration::from_secs(30),
        hash_key: HashKey::configured("a fixture hash key"),
        image_config: None,
        jobs: 1,
        network: network.then(Proxies::default),
        containers: false,
    }
}

#[test]
fn a_network_collector_runs_only_when_asked_and_only_on_the_live_host() {
    let probe = Collector::parse(
        "id: web\nnetwork: true\nread: {addr: [\"127.0.0.1:1\"]}\nparse: {plugin: formats, op: probes}\ninto: probes\n",
    )
    .unwrap();
    let outcome = |options: &Options| {
        collect::collect(std::slice::from_ref(&probe), &[], options)["collectors"]["web"].clone()
    };
    let off = outcome(&options(true, false));
    assert_eq!(off["status"], "skipped");
    assert!(off["reason"].as_str().unwrap().contains("--network"));
    let root = outcome(&options(false, true));
    assert_eq!(root["status"], "skipped");
    assert!(root["reason"].as_str().unwrap().contains("--root"));
    let on = outcome(&options(true, true));
    assert_eq!(on["status"], "error", "{on}");
    assert!(
        on["reason"]
            .as_str()
            .unwrap()
            .contains("systemlint-formats")
    );
}

#[test]
fn a_collector_declares_network_exactly_when_it_probes_and_probes_alone() {
    let parse = |read: &str, network: bool| {
        Collector::parse(&format!(
            "id: c\nnetwork: {network}\nread: {read}\nparse: {{plugin: formats, op: probes}}\ninto: probes\n"
        ))
    };
    assert!(parse("{addr: [\"kiota.ch:443\"]}", true).is_ok());
    assert!(
        parse("{addr: [\"kiota.ch:443\"]}", false)
            .unwrap_err()
            .contains("network: true")
    );
    assert!(
        parse("{files: [/etc/hosts]}", true)
            .unwrap_err()
            .contains("no addr, dns or http")
    );
    let mixed = parse("{addr: [\"kiota.ch:443\"], files: [/etc/hosts]}", true);
    assert!(mixed.unwrap_err().contains("reads only addr, dns and http"));
    assert!(
        parse("{dns: [kiota.ch], dns-types: [ANY]}", true)
            .unwrap_err()
            .contains("dns-types")
    );
    assert!(parse("{addr: [\"kiota.ch:0\"]}", true).is_err());
    assert!(
        parse(
            "{dns: [\".\"], dns-server-from: [resolv.conf.*.nameserver.:3]}",
            true
        )
        .is_ok()
    );
    for (read, why) in [
        (
            "{dns-server-from: [resolv.conf.*.nameserver.:3]}",
            "no addr, dns or http",
        ),
        (
            "{http: [\"https://kiota.ch/\"], dns-server-from: [a.b]}",
            "list one",
        ),
        (
            "{dns: [x.test], dns-server: \"192.0.2.1\", dns-server-from: [a.b]}",
            "keep one",
        ),
        (
            "{dns: [x.test], dns-server-from: [\"{a.b}\"]}",
            "never a {template}",
        ),
        (
            "{dns: [x.test], dns-server-from: [\"*.b\"]}",
            "starts with a wildcard",
        ),
        (
            "{dns: [x.test], dns-server-from: [probes.x]}",
            "which this collector writes",
        ),
    ] {
        let error = parse(read, true).unwrap_err();
        assert!(error.contains(why), "{read}: {error}");
    }
    let http = |entry: &str| parse(&format!("{{http: [{entry}]}}"), true);
    assert!(http("https://kiota.ch/").is_ok());
    assert!(http("{url: \"https://kiota.ch/\", username: u, password-file: /run/p, ca-file: /etc/ca.pem, body: json}").is_ok());
    assert!(http("ftp://kiota.ch/").unwrap_err().contains("scheme ftp"));
    assert!(
        http("\"https://u:p@kiota.ch/\"")
            .unwrap_err()
            .contains("password-file")
    );
    assert!(
        http("{url: \"http://kiota.ch/\", username: u, password-file: /run/p}")
            .unwrap_err()
            .contains("only over https")
    );
    assert!(
        http("{url: \"https://kiota.ch/\", username: u}")
            .unwrap_err()
            .contains("go together")
    );
    assert!(
        http("{url: \"https://kiota.ch/\", username: u, password-file: p}")
            .unwrap_err()
            .contains("absolute")
    );
    assert!(
        http("{url: \"http://kiota.ch/\", ca-file: /etc/ca.pem}")
            .unwrap_err()
            .contains("not https")
    );
}

#[test]
fn the_closing_line_names_each_probed_nameserver_not_the_name_asked() {
    let parse = |text: &str| Collector::parse(text).unwrap();
    let collectors = [
        parse(
            "id: web\nnetwork: true\nread: {addr: [\"kiota.ch:443\"], dns: [kiota.ch]}\nparse: {plugin: formats, op: probes}\ninto: probes.web\n",
        ),
        parse(
            "id: ns\nnetwork: true\nread: {dns: [\".\"], dns-server-from: [resolv.conf.*.nameserver.:3]}\nparse: {plugin: formats, op: probes}\ninto: resolv.probes\n",
        ),
    ];
    let document = json!({
        "resolv": {"probes": {"nameserver": {"192.0.2.1": {"answered": true}, "192.0.2.2": {"answered": false}}}},
        "collectors": {"web": {"status": "ok"}, "ns": {"status": "ok"}}
    });
    assert_eq!(
        systemlint::progress::reached(&document, &collectors),
        ["kiota.ch:443", "kiota.ch", "192.0.2.1", "192.0.2.2"]
    );
}
