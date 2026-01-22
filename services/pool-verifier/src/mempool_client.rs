use serde::Deserialize;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

fn client() -> &'static reqwest::Client {
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_millis(900))
            .build()
            .expect("reqwest client")
    })
}

#[derive(Deserialize)]
struct MempoolSnapshot {
    // template-manager /mempool => "tx_count"
    // older/alt shapes may use "count" or "size"
    #[serde(default, alias = "tx_count", alias = "count", alias = "size")]
    tx_count: u64,

    // unix seconds if provided
    #[serde(default)]
    timestamp: Option<u64>,
}

pub fn mempool_url_from_env() -> Option<String> {
    std::env::var("VELDRA_MEMPOOL_URL").ok()
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

pub async fn fetch_mempool_tx_count(url: &str) -> Option<u64> {
    let resp = match client().get(url).send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[mempool_client] HTTP error fetching {}: {e:?}", url);
            return None;
        }
    };

    let status = resp.status();
    if !status.is_success() {
        eprintln!(
            "[mempool_client] non-success status {} from {}",
            status, url
        );
        return None;
    }

    let snapshot = match resp.json::<MempoolSnapshot>().await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[mempool_client] JSON parse error from {}: {e:?}", url);
            return None;
        }
    };

    if let Some(ts) = snapshot.timestamp {
        let age = now_unix_secs().saturating_sub(ts);
        if age > 30 {
            eprintln!("[mempool_client] stale snapshot from {}: age={}s", url, age);
        }
    }

    Some(snapshot.tx_count)
}
