use anyhow::{Context, Result};
use axum::{
    extract::State,
    response::{Html, IntoResponse},
    routing::get,
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use clap::Parser;
use hickory_proto::{
    op::Message,
    serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder},
};
use serde::Serialize;
use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::Arc,
};
use tokio::{net::UdpSocket, sync::RwLock};
use tracing::{error, info, warn};

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "DNS Müfettişi - DNS sorgularını loglayıp DoH ile ileten örnek proje")]
struct Args {
    /// UDP dinleme adresi (root istememesi için varsayılan 5353)
    #[arg(long, default_value = "127.0.0.1:5353")]
    listen: SocketAddr,

    /// HTTP dashboard adresi
    #[arg(long, default_value = "127.0.0.1:8080")]
    dashboard: SocketAddr,

    /// DoH upstream URL
    #[arg(long, default_value = "https://cloudflare-dns.com/dns-query")]
    doh: String,

    /// Bellekte tutulacak maksimum log kaydı
    #[arg(long, default_value_t = 200)]
    max_logs: usize,
}

#[derive(Debug, Clone, Serialize)]
struct DnsEvent {
    timestamp: DateTime<Utc>,
    client: String,
    id: u16,
    query_names: Vec<String>,
    query_types: Vec<String>,
}

#[derive(Clone)]
struct AppState {
    events: Arc<RwLock<VecDeque<DnsEvent>>>,
    max_logs: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "dns_mufettisi=info,tower_http=info,info".to_string()),
        )
        .init();

    let args = Args::parse();
    let state = AppState {
        events: Arc::new(RwLock::new(VecDeque::with_capacity(args.max_logs))),
        max_logs: args.max_logs,
    };

    let dns_state = state.clone();
    let doh_url = args.doh.clone();
    tokio::spawn(async move {
        if let Err(err) = run_dns_proxy(args.listen, doh_url, dns_state).await {
            error!("DNS proxy durdu: {err:#}");
        }
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/api/events", get(list_events))
        .with_state(state);

    info!("Dashboard hazır: http://{}", args.dashboard);
    let listener = tokio::net::TcpListener::bind(args.dashboard)
        .await
        .context("dashboard portuna bind olunamadı")?;
    axum::serve(listener, app).await.context("dashboard çöktü")?;
    Ok(())
}

async fn run_dns_proxy(listen: SocketAddr, doh_url: String, state: AppState) -> Result<()> {
    let socket = UdpSocket::bind(listen)
        .await
        .with_context(|| format!("UDP socket bind başarısız: {listen}"))?;
    info!("DNS dinleyici hazır: udp://{listen}");
    info!("DoH upstream: {doh_url}");

    let client = reqwest::Client::builder()
        .user_agent("dns-mufettisi/0.1")
        .use_rustls_tls()
        .build()
        .context("HTTP istemcisi oluşturulamadı")?;

    loop {
        let mut buf = [0u8; 4096];
        let (len, peer) = socket.recv_from(&mut buf).await.context("UDP recv başarısız")?;
        let packet = buf[..len].to_vec();

        let client = client.clone();
        let socket = socket.clone();
        let doh_url = doh_url.clone();
        let state = state.clone();

        tokio::spawn(async move {
            if let Err(err) = handle_query(packet, peer, socket, client, &doh_url, state).await {
                warn!("{} istemcisinin sorgusu işlenemedi: {err:#}", peer);
            }
        });
    }
}

async fn handle_query(
    packet: Vec<u8>,
    peer: SocketAddr,
    socket: UdpSocket,
    client: reqwest::Client,
    doh_url: &str,
    state: AppState,
) -> Result<()> {
    let message = Message::from_vec(&packet).context("DNS paketi parse edilemedi")?;
    let query_names = message
        .queries()
        .iter()
        .map(|q| q.name().to_utf8())
        .collect::<Vec<_>>();
    let query_types = message
        .queries()
        .iter()
        .map(|q| format!("{:?}", q.query_type()))
        .collect::<Vec<_>>();

    let event = DnsEvent {
        timestamp: Utc::now(),
        client: peer.to_string(),
        id: message.id(),
        query_names,
        query_types,
    };

    append_event(&state, event).await;

    let response = doh_exchange(&client, doh_url, &packet).await?;
    socket
        .send_to(&response, peer)
        .await
        .context("DNS cevabı UDP ile geri yollanamadı")?;
    Ok(())
}

async fn doh_exchange(client: &reqwest::Client, doh_url: &str, packet: &[u8]) -> Result<Vec<u8>> {
    let encoded = URL_SAFE_NO_PAD.encode(packet);
    let url = format!("{doh_url}?dns={encoded}");

    let response = client
        .get(url)
        .header("accept", "application/dns-message")
        .send()
        .await
        .context("DoH isteği başarısız")?
        .error_for_status()
        .context("DoH upstream hata döndü")?;

    let body: Bytes = response.bytes().await.context("DoH cevabı okunamadı")?;

    // Hickory ile hızlı doğrulama: cevap gerçekten DNS message mı?
    let mut decoder = BinDecoder::new(&body);
    let _ = Message::read(&mut decoder).context("DoH cevabı geçersiz DNS message")?;

    Ok(body.to_vec())
}

async fn append_event(state: &AppState, event: DnsEvent) {
    let mut guard = state.events.write().await;
    if guard.len() >= state.max_logs {
        let _ = guard.pop_front();
    }
    guard.push_back(event);
}

async fn list_events(State(state): State<AppState>) -> Json<Vec<DnsEvent>> {
    let guard = state.events.read().await;
    Json(guard.iter().cloned().rev().collect())
}

async fn index() -> impl IntoResponse {
    Html(INDEX_HTML)
}

const INDEX_HTML: &str = r#"<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>DNS Müfettişi</title>
  <style>
    :root { color-scheme: dark; }
    body {
      margin: 0; font-family: Inter, system-ui, Arial, sans-serif;
      background: #0f172a; color: #e5e7eb;
    }
    .wrap { max-width: 1080px; margin: 0 auto; padding: 32px 20px 64px; }
    .hero, .card {
      background: linear-gradient(180deg, rgba(30,41,59,.95), rgba(15,23,42,.98));
      border: 1px solid rgba(148,163,184,.18); border-radius: 22px;
      box-shadow: 0 20px 40px rgba(0,0,0,.25);
    }
    .hero { padding: 28px; margin-bottom: 24px; }
    .badge {
      display: inline-block; padding: 10px 16px; border-radius: 999px;
      border: 1px solid #4f46e5; color: #c4b5fd; margin-bottom: 18px;
      font-weight: 700; font-size: 14px;
    }
    h1 { font-size: clamp(32px, 5vw, 54px); margin: 0 0 12px; color: #818cf8; }
    p { line-height: 1.7; color: #cbd5e1; }
    .mini {
      margin-top: 18px; background: rgba(13,148,136,.1); border: 1px solid rgba(13,148,136,.35);
      border-radius: 18px; padding: 18px;
    }
    .grid { display: grid; grid-template-columns: 1fr; gap: 16px; }
    @media (min-width: 900px) { .grid { grid-template-columns: 1fr 1fr; } }
    .card { padding: 22px; }
    table { width: 100%; border-collapse: collapse; }
    th, td { text-align: left; padding: 10px 8px; border-bottom: 1px solid rgba(148,163,184,.16); }
    th { color: #a5b4fc; }
    code {
      background: rgba(15,23,42,.8); border: 1px solid rgba(148,163,184,.16); padding: 3px 6px;
      border-radius: 8px; color: #93c5fd;
    }
    .muted { color: #94a3b8; }
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <div class="badge">Temel &amp; Orta Seviye</div>
      <h1>7. DNS Müfettişi</h1>
      <p>DNS sorgularını yakalayan, hangi sitelere gidilmeye çalışıldığını gösteren ve sorguları güvenli şekilde <strong>DNS-over-HTTPS (DoH)</strong> ile upstream sunucuya ileten küçük bir GitHub projesi.</p>
      <div class="mini">
        <strong>Kısa Yol Haritası</strong>
        <p class="muted">Sorguyu yakala → alan adını logla → paketi DoH ile ilet → cevabı geri dön → dashboard'da göster.</p>
      </div>
    </section>

    <section class="grid">
      <article class="card">
        <h2>Nasıl çalışır?</h2>
        <p>Uygulama UDP üzerinde gelen DNS paketlerini dinler, sorgu adlarını çıkarır, bellekte tutar ve aynı ham DNS paketini bir DoH sağlayıcısına yollar. Dönüşte gelen DNS cevabını istemciye geri yollar.</p>
        <p><strong>Varsayılan port:</strong> <code>127.0.0.1:5353</code></p>
        <p><strong>Dashboard:</strong> <code>http://127.0.0.1:8080</code></p>
      </article>

      <article class="card">
        <h2>Canlı sorgular</h2>
        <table id="events">
          <thead>
            <tr><th>Zaman</th><th>İstemci</th><th>Domain</th><th>Tip</th></tr>
          </thead>
          <tbody></tbody>
        </table>
      </article>
    </section>
  </div>
  <script>
    async function refresh() {
      const res = await fetch('/api/events');
      const data = await res.json();
      const tbody = document.querySelector('#events tbody');
      tbody.innerHTML = '';
      for (const item of data) {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${new Date(item.timestamp).toLocaleString('tr-TR')}</td>
          <td>${item.client}</td>
          <td>${(item.query_names || []).join('<br>')}</td>
          <td>${(item.query_types || []).join(', ')}</td>
        `;
        tbody.appendChild(tr);
      }
    }
    refresh();
    setInterval(refresh, 1500);
  </script>
</body>
</html>"#;
