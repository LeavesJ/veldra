use std::time::Duration;
use serde::Deserialize;

#[derive(Deserialize)]
struct MempoolSnapshot {
    tx_count: u64,
}

pub fn mempool_url_from_env() -> Option<String> {
    std::env::var("VELDRA_MEMPOOL_URL").ok()
}

pub async fn fetch_mempool_tx_count(url: &str) -> Option<u64> {
    let client = reqwest::Client::new();

    let resp = match client
        .get(url)
        .timeout(Duration::from_secs(2))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[mempool_client] HTTP error fetching {}: {e:?}", url);
            return None;
        }
    };

    let status = resp.status();
    if !status.is_success() {
        eprintln!(
            "[mempool_client] non success status {} from {}",
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

    Some(snapshot.tx_count)
}
