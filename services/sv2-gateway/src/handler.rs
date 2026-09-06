//! Per-connection SV2 session handler.
//!
//! After the Noise NX handshake completes (in `accept_loop`), each TCP
//! connection is handed off to [`run_connection`] which drives the full
//! SV2 session lifecycle:
//!
//! 1. `SetupConnection` exchange (validate protocol version 2 + flags).
//! 2. Channel open (`OpenStandardMiningChannel` -> auth check -> allocate
//!    `channel_id` + extranonce -> Success + `SetTarget` + initial `NewMiningJob`;
//!    reject Extended channels with close).
//! 3. Steady-state `select!` loop:
//!    - `job_rx` broadcast: distribute `NewMiningJob` + optional `SetNewPrevHash`
//!    - `transport.read_frame()`: handle `SubmitSharesStandard`,
//!      `OpenStandardMiningChannel` (additional channels), `CloseChannel`
//!    - Shutdown signal -> drain and disconnect.
//! 4. `DisconnectEvent` emission with telemetry.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use reservegrid_common::reason::GatewayReason;
use tokio::sync::{broadcast, mpsc, watch};
use tracing::{debug, info, warn};

use crate::channels::{
    ChannelIdAllocator, ChannelKind, ConnectionChannels, ExtranonceAllocator,
    SharedChannelRegistry, snapshot_from_open,
};
use crate::connection::{DisconnectEvent, PeerState};
use crate::jobs::JobTable;
use crate::shares::{
    self, ShareAcceptedEvent, ShareDedupSet, ShareSubmission, check_ntime_bounds,
    check_version_bits, compute_event_id, compute_share_id, current_unix_timestamp,
    header_identity_bytes, sign_submission, unix_ms_now, validate_share_pow,
};
use crate::sv2_codec::{
    self, MESSAGE_TYPE_CLOSE_CHANNEL, MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH,
    MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB, MESSAGE_TYPE_NEW_MINING_JOB,
    MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL, MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
    MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR, MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL,
    MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS, MESSAGE_TYPE_SET_TARGET,
    MESSAGE_TYPE_SETUP_CONNECTION, MESSAGE_TYPE_SETUP_CONNECTION_ERROR,
    MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS, MESSAGE_TYPE_SUBMIT_SHARES_ERROR,
    MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED, MESSAGE_TYPE_SUBMIT_SHARES_STANDARD,
    MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS,
};
use crate::transport::{Sv2FrameHeader, Sv2Transport};
use prometheus_client::metrics::counter::Counter;

// ─────────────────────────────────────────────────────────────────────
// Job broadcast payload
// ─────────────────────────────────────────────────────────────────────

/// Payload broadcast from the main event loop to all connection handlers
/// when a verified job is ready for distribution.
#[derive(Debug, Clone)]
pub struct JobBroadcast {
    /// The gateway-assigned job ID.
    pub job_id: u32,
    /// Block version (with BIP 320 GP bits set as desired).
    pub version: u32,
    /// Coinbase transaction prefix (before extranonce).
    pub coinbase_tx_prefix: Vec<u8>,
    /// Coinbase transaction suffix (after extranonce).
    pub coinbase_tx_suffix: Vec<u8>,
    /// Merkle path: sibling hashes from coinbase leaf to root.
    pub merkle_path: Vec<[u8; 32]>,
    /// If `Some`, this job is tied to a new prevhash and the handler must
    /// also send `SetNewPrevHash`.
    pub prevhash_update: Option<PrevhashUpdate>,
    /// When `Some`, this is an intra-block refresh (same prevhash, new job)
    /// and `min_ntime` should be set on the `NewMiningJob`.
    pub min_ntime: Option<u32>,
}

/// Prevhash change accompanying a job broadcast.
#[derive(Debug, Clone)]
pub struct PrevhashUpdate {
    pub prev_hash: [u8; 32],
    pub min_ntime: u32,
    pub nbits: u32,
}

// ─────────────────────────────────────────────────────────────────────
// Handler errors
// ─────────────────────────────────────────────────────────────────────

/// Reasons a connection handler terminates.
#[derive(Debug)]
pub enum HandlerExit {
    /// Peer sent invalid `SetupConnection`.
    SetupRejected(String),
    /// Peer closed the connection or transport error.
    TransportError(crate::transport::TransportError),
    /// Gateway is shutting down.
    Shutdown,
    /// Peer did not open any channel within the timeout.
    ChannelOpenTimeout,
    /// Codec error decoding a message.
    CodecError(sv2_codec::Sv2CodecError),
}

impl std::fmt::Display for HandlerExit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandlerExit::SetupRejected(s) => write!(f, "setup rejected: {s}"),
            HandlerExit::TransportError(e) => write!(f, "transport: {e}"),
            HandlerExit::Shutdown => write!(f, "shutdown"),
            HandlerExit::ChannelOpenTimeout => write!(f, "channel open timeout"),
            HandlerExit::CodecError(e) => write!(f, "codec: {e}"),
        }
    }
}

impl HandlerExit {
    /// Map this exit reason to a canonical `GatewayReason` for disconnect telemetry.
    pub fn as_gateway_reason(&self) -> GatewayReason {
        match self {
            HandlerExit::SetupRejected(_) => GatewayReason::SetupConnectionRejected,
            HandlerExit::TransportError(_) => GatewayReason::PeerTransportError,
            HandlerExit::Shutdown => GatewayReason::ShutdownDrain,
            HandlerExit::ChannelOpenTimeout => GatewayReason::ChannelOpenTimeout,
            HandlerExit::CodecError(_) => GatewayReason::FrameDecodeError,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Connection handler
// ─────────────────────────────────────────────────────────────────────

/// Configuration for a single connection handler.
pub struct HandlerConfig {
    /// Maximum standard mining channels per connection.
    pub max_channels_per_conn: u32,
    /// Share acceptance target for new channels (static difficulty V1.0.0).
    pub channel_target: [u8; 32],
    /// Timeout for the initial channel open after `SetupConnection`.
    pub channel_open_timeout: Duration,
    /// Ntime elapsed slack in seconds (absorbs network latency).
    pub ntime_elapsed_slack_seconds: u32,
    /// Max future block time in seconds (Bitcoin consensus default 7200).
    pub max_future_block_time_seconds: u32,
    /// Share deduplication window size (inline mode replay detection).
    pub share_dedup_window_size: usize,
    /// Maximum share submissions per second per channel. 0 means unlimited.
    pub max_shares_per_second_per_channel: u32,
    /// Gateway instance identifier embedded in share submissions.
    pub gateway_instance_id: String,
    /// HMAC secret bytes for signing share event IDs. Empty disables signing.
    /// Behind `RwLock` to support SIGHUP-triggered rotation without restart.
    pub share_hmac_secret: Arc<std::sync::RwLock<Vec<u8>>>,
    /// Whether extended mining channels are accepted. When false, extended
    /// channel open requests are rejected with `CloseChannel`.
    pub extended_channels_enabled: bool,
    /// Extranonce prefix length in bytes (from config). Used for computing
    /// total `extranonce_size` in extended channel negotiation.
    pub extranonce_prefix_len: usize,
    /// Enable variable difficulty adjustment per channel.
    pub vardiff_enabled: bool,
    /// Target shares per minute per channel (vardiff).
    pub vardiff_target_shares_per_min: f64,
    /// Retarget evaluation interval (vardiff).
    pub vardiff_retarget_interval: Duration,
    /// Minimum difficulty floor (vardiff).
    pub vardiff_min_difficulty: u64,
    /// Maximum difficulty ceiling (vardiff).
    pub vardiff_max_difficulty: u64,
    /// Maximum multiplicative adjustment factor per retarget (vardiff).
    pub vardiff_max_adjustment_factor: f64,
}

/// All resources needed to run a single connection handler.
pub struct ConnectionContext {
    pub transport: Sv2Transport,
    pub peer: SocketAddr,
    pub config: Arc<HandlerConfig>,
    pub channel_id_alloc: Arc<ChannelIdAllocator>,
    pub extranonce_alloc: Arc<ExtranonceAllocator>,
    pub job_table: Arc<tokio::sync::RwLock<JobTable>>,
    pub latest_job: Arc<tokio::sync::RwLock<Option<Arc<JobBroadcast>>>>,
    pub job_rx: broadcast::Receiver<Arc<JobBroadcast>>,
    pub share_event_tx: mpsc::Sender<ShareAcceptedEvent>,
    pub share_forward_tx: mpsc::Sender<ShareSubmission>,
    pub shutdown: watch::Receiver<bool>,
    pub permit: tokio::sync::OwnedSemaphorePermit,
    pub channel_registry: SharedChannelRegistry,
    pub vardiff_retarget_up: Counter,
    pub vardiff_retarget_down: Counter,
}

/// Run the full SV2 session lifecycle for one connection.
///
/// This function is spawned as an async task per accepted TCP connection,
/// after the Noise NX handshake has already completed. On every exit path
/// a structured `DisconnectEvent` is emitted for observability.
pub async fn run_connection(ctx: ConnectionContext) -> HandlerExit {
    let ConnectionContext {
        mut transport,
        peer,
        config,
        channel_id_alloc,
        extranonce_alloc,
        job_table,
        latest_job,
        mut job_rx,
        share_event_tx,
        share_forward_tx,
        mut shutdown,
        permit: _permit,
        channel_registry,
        vardiff_retarget_up,
        vardiff_retarget_down,
    } = ctx;
    let peer_state = PeerState::new(peer);
    let mut share_dedup = ShareDedupSet::new(config.share_dedup_window_size);

    let (exit, opened_channel_ids) = run_connection_inner(
        &mut transport,
        peer,
        &peer_state,
        &config,
        &channel_id_alloc,
        &extranonce_alloc,
        &job_table,
        &latest_job,
        &mut job_rx,
        &share_event_tx,
        &share_forward_tx,
        &mut shutdown,
        &mut share_dedup,
        &channel_registry,
        &vardiff_retarget_up,
        &vardiff_retarget_down,
    )
    .await;

    // Unregister all channels that were opened on this connection.
    for ch_id in opened_channel_ids {
        channel_registry.unregister(ch_id).await;
    }

    // Emit structured disconnect event for every exit path.
    let reason = exit.as_gateway_reason();
    peer_state.set_disconnect_reason(reason);
    DisconnectEvent::from_peer(&peer_state, reason).log();

    exit
}

/// Inner session lifecycle, extracted so `run_connection` can unconditionally
/// emit a `DisconnectEvent` after this returns.
///
/// Returns the handler exit reason and a list of channel IDs that were opened
/// during this connection (for global registry cleanup).
#[allow(clippy::too_many_arguments)]
async fn run_connection_inner(
    transport: &mut Sv2Transport,
    peer: SocketAddr,
    peer_state: &PeerState,
    config: &Arc<HandlerConfig>,
    channel_id_alloc: &Arc<ChannelIdAllocator>,
    extranonce_alloc: &Arc<ExtranonceAllocator>,
    job_table: &Arc<tokio::sync::RwLock<JobTable>>,
    latest_job: &Arc<tokio::sync::RwLock<Option<Arc<JobBroadcast>>>>,
    job_rx: &mut broadcast::Receiver<Arc<JobBroadcast>>,
    share_event_tx: &mpsc::Sender<ShareAcceptedEvent>,
    share_forward_tx: &mpsc::Sender<ShareSubmission>,
    shutdown: &mut watch::Receiver<bool>,
    share_dedup: &mut ShareDedupSet,
    channel_registry: &SharedChannelRegistry,
    vardiff_retarget_up: &Counter,
    vardiff_retarget_down: &Counter,
) -> (HandlerExit, Vec<u32>) {
    let mut opened_ids: Vec<u32> = Vec::new();

    // ── Stage 1: SetupConnection ──
    let setup_result = handle_setup_connection(transport, peer_state).await;
    if let Err(exit) = setup_result {
        return (exit, opened_ids);
    }

    // ── Stage 2+3: Channel open + steady-state loop ──
    let mut channels = ConnectionChannels::new(config.max_channels_per_conn);

    // Wait for first channel open or timeout.
    let first_channel = tokio::time::timeout(
        config.channel_open_timeout,
        wait_for_channel_open(
            transport,
            peer_state,
            &mut channels,
            channel_id_alloc,
            extranonce_alloc,
            config,
            latest_job,
            channel_registry,
            peer,
            &mut opened_ids,
        ),
    )
    .await;

    match first_channel {
        Err(_elapsed) => {
            warn!(peer = %peer, "no channel open within timeout");
            return (HandlerExit::ChannelOpenTimeout, opened_ids);
        }
        Ok(Err(exit)) => return (exit, opened_ids),
        Ok(Ok(())) => {}
    }

    // ── Stage 3: Steady-state select loop ──
    loop {
        tokio::select! {
            // New job from main event loop.
            job_result = job_rx.recv() => {
                match job_result {
                    Ok(job) => {
                        if let Err(exit) = distribute_job(transport, &mut channels, &job).await {
                            return (exit, opened_ids);
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!(peer = %peer, lagged = n, "job broadcast lagged; catching up");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        info!(peer = %peer, "job broadcast closed; shutting down handler");
                        return (HandlerExit::Shutdown, opened_ids);
                    }
                }
            }
            // Incoming SV2 frame from miner.
            frame_result = transport.read_frame() => {
                match frame_result {
                    Ok((header, payload)) => {
                        let action = handle_miner_frame(
                            transport,
                            peer_state,
                            &mut channels,
                            channel_id_alloc,
                            extranonce_alloc,
                            config,
                            job_table,
                            latest_job,
                            share_dedup,
                            share_event_tx,
                            share_forward_tx,
                            &header,
                            &payload,
                            channel_registry,
                            peer,
                            &mut opened_ids,
                            vardiff_retarget_up,
                            vardiff_retarget_down,
                        ).await;
                        match action {
                            FrameAction::Continue => {}
                            FrameAction::Disconnect(exit) => return (exit, opened_ids),
                        }
                    }
                    Err(e) => {
                        debug!(peer = %peer, error = %e, "transport read error");
                        return (HandlerExit::TransportError(e), opened_ids);
                    }
                }
            }
            // Shutdown signal.
            _ = shutdown.changed() => {
                info!(peer = %peer, "handler received shutdown signal");
                return (HandlerExit::Shutdown, opened_ids);
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Stage 1: SetupConnection
// ─────────────────────────────────────────────────────────────────────

/// Best-effort: encode and send a `SetupConnection.Error` frame. Failures are
/// logged at debug level and swallowed because the connection is about to close.
async fn send_setup_error(transport: &mut Sv2Transport, flags: u32) {
    let err_msg = sv2_codec::SetupConnectionError {
        flags,
        error_code: "unsupported-protocol".to_string(),
    };
    if let Ok(err_payload) = err_msg.encode()
        && let Err(e) = transport
            .write_frame(0x0000, MESSAGE_TYPE_SETUP_CONNECTION_ERROR, &err_payload)
            .await
    {
        debug!(error = %e, "best-effort SetupConnection.Error write failed");
    }
}

async fn handle_setup_connection(
    transport: &mut Sv2Transport,
    peer_state: &PeerState,
) -> Result<(), HandlerExit> {
    let (header, payload) = transport
        .read_frame()
        .await
        .map_err(HandlerExit::TransportError)?;

    // Reject non-base-protocol extension types (lower 15 bits must be 0).
    if header.extension_type & 0x7FFF != 0 {
        let reason = format!(
            "unsupported extension_type 0x{:04x}; only base mining protocol (0x0000/0x8000) is supported",
            header.extension_type,
        );
        return Err(HandlerExit::SetupRejected(reason));
    }

    if header.msg_type != MESSAGE_TYPE_SETUP_CONNECTION {
        let reason = format!(
            "expected SetupConnection (0x{:02x}), got 0x{:02x}",
            MESSAGE_TYPE_SETUP_CONNECTION, header.msg_type,
        );
        send_setup_error(transport, 0).await;
        return Err(HandlerExit::SetupRejected(reason));
    }

    let setup = match sv2_codec::SetupConnection::decode(&payload) {
        Ok(s) => s,
        Err(e) => {
            send_setup_error(transport, 0).await;
            return Err(HandlerExit::CodecError(e));
        }
    };

    // Validate: protocol must be MiningProtocol (0), version range must include 2.
    if setup.protocol != 0 {
        send_setup_error(transport, 0).await;
        return Err(HandlerExit::SetupRejected(format!(
            "protocol {} is not MiningProtocol",
            setup.protocol,
        )));
    }

    if setup.min_version > 2 || setup.max_version < 2 {
        send_setup_error(transport, setup.flags).await;
        return Err(HandlerExit::SetupRejected(format!(
            "version range [{}, {}] does not include 2",
            setup.min_version, setup.max_version,
        )));
    }

    debug!(
        peer = %peer_state.peer_addr,
        vendor = %setup.vendor,
        firmware = %setup.firmware,
        "SetupConnection accepted",
    );

    // Send SetupConnection.Success.
    let success = sv2_codec::SetupConnectionSuccess {
        used_version: 2,
        flags: 0, // No special flags in V1.0.0.
    };
    let success_payload = success.encode().map_err(HandlerExit::CodecError)?;
    transport
        .write_frame(
            0x0000,
            MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
            &success_payload,
        )
        .await
        .map_err(HandlerExit::TransportError)?;

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────
// Stage 2: Channel open
// ─────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn wait_for_channel_open(
    transport: &mut Sv2Transport,
    peer_state: &PeerState,
    channels: &mut ConnectionChannels,
    channel_id_alloc: &ChannelIdAllocator,
    extranonce_alloc: &ExtranonceAllocator,
    config: &HandlerConfig,
    latest_job: &Arc<tokio::sync::RwLock<Option<Arc<JobBroadcast>>>>,
    channel_registry: &SharedChannelRegistry,
    peer: SocketAddr,
    opened_ids: &mut Vec<u32>,
) -> Result<(), HandlerExit> {
    loop {
        let (header, payload) = transport
            .read_frame()
            .await
            .map_err(HandlerExit::TransportError)?;

        // Reject non-base-protocol extension types.
        if header.extension_type & 0x7FFF != 0 {
            warn!(
                peer = %peer_state.peer_addr,
                extension_type = header.extension_type,
                "unsupported extension_type; disconnecting",
            );
            return Err(HandlerExit::SetupRejected(format!(
                "unsupported extension_type 0x{:04x}",
                header.extension_type,
            )));
        }

        match header.msg_type {
            MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL => {
                handle_open_standard_channel(
                    transport,
                    peer_state,
                    channels,
                    channel_id_alloc,
                    extranonce_alloc,
                    config,
                    latest_job,
                    &payload,
                    channel_registry,
                    peer,
                    opened_ids,
                )
                .await?;
                return Ok(());
            }
            MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL => {
                if !config.extended_channels_enabled {
                    return Err(reject_extended_channel_err(transport).await);
                }
                handle_open_extended_channel(
                    transport,
                    peer_state,
                    channels,
                    channel_id_alloc,
                    extranonce_alloc,
                    config,
                    latest_job,
                    &payload,
                    channel_registry,
                    peer,
                    opened_ids,
                )
                .await?;
                return Ok(());
            }
            other => {
                debug!(
                    peer = %peer_state.peer_addr,
                    msg_type = other,
                    "unexpected message before channel open; ignoring",
                );
            }
        }
    }
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn handle_open_standard_channel(
    transport: &mut Sv2Transport,
    peer_state: &PeerState,
    channels: &mut ConnectionChannels,
    channel_id_alloc: &ChannelIdAllocator,
    extranonce_alloc: &ExtranonceAllocator,
    config: &HandlerConfig,
    latest_job: &Arc<tokio::sync::RwLock<Option<Arc<JobBroadcast>>>>,
    payload: &[u8],
    channel_registry: &SharedChannelRegistry,
    peer: SocketAddr,
    opened_ids: &mut Vec<u32>,
) -> Result<(), HandlerExit> {
    let open_req = match sv2_codec::OpenStandardMiningChannel::decode(payload) {
        Ok(r) => r,
        Err(e) => {
            // Best effort: send OpenMiningChannel.Error with request_id=0 since
            // the decode failed and we cannot extract the real request_id.
            let err = sv2_codec::OpenMiningChannelError {
                request_id: 0,
                error_code: "unsupported-protocol".to_string(),
            };
            if let Ok(err_payload) = err.encode()
                && let Err(we) = transport
                    .write_frame(0x0000, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR, &err_payload)
                    .await
            {
                debug!(error = %we, "best-effort OpenMiningChannel.Error write failed");
            }
            return Err(HandlerExit::CodecError(e));
        }
    };

    // Allocate channel ID and extranonce.
    let Some(channel_id) = channel_id_alloc.allocate() else {
        warn!(
            peer = %peer_state.peer_addr,
            "channel_id allocation exhausted; rejecting OpenStandardMiningChannel",
        );
        let err = sv2_codec::OpenMiningChannelError {
            request_id: open_req.request_id,
            error_code: "max-target-out-of-range".to_string(),
        };
        if let Ok(err_payload) = err.encode()
            && let Err(e) = transport
                .write_frame(0x0000, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR, &err_payload)
                .await
        {
            debug!(error = %e, "best-effort OpenMiningChannel.Error write failed");
        }
        return Err(HandlerExit::SetupRejected(
            "channel_id allocator exhausted".to_string(),
        ));
    };

    let Some(extranonce) = extranonce_alloc.allocate() else {
        warn!(
            peer = %peer_state.peer_addr,
            "extranonce allocation exhausted; rejecting OpenStandardMiningChannel",
        );
        let err = sv2_codec::OpenMiningChannelError {
            request_id: open_req.request_id,
            error_code: "max-target-out-of-range".to_string(),
        };
        if let Ok(err_payload) = err.encode()
            && let Err(e) = transport
                .write_frame(0x0000, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR, &err_payload)
                .await
        {
            debug!(error = %e, "best-effort OpenMiningChannel.Error write failed");
        }
        return Err(HandlerExit::SetupRejected(
            "extranonce allocator exhausted".to_string(),
        ));
    };

    // Clone extranonce before moving into channel state (Vec is not Copy).
    let extranonce_for_reply = extranonce.clone();

    // Register in connection channels.
    if let Err(reason) = channels.open_channel(
        channel_id,
        extranonce,
        open_req.user_identity.clone(),
        None,
        config.channel_target,
        config.max_shares_per_second_per_channel,
    ) {
        warn!(
            peer = %peer_state.peer_addr,
            reason = %reason,
            "channel registration failed; rejecting OpenStandardMiningChannel",
        );
        let err = sv2_codec::OpenMiningChannelError {
            request_id: open_req.request_id,
            error_code: "max-target-out-of-range".to_string(),
        };
        if let Ok(err_payload) = err.encode()
            && let Err(e) = transport
                .write_frame(0x0000, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR, &err_payload)
                .await
        {
            debug!(error = %e, "best-effort OpenMiningChannel.Error write failed");
        }
        return Err(HandlerExit::SetupRejected(format!(
            "channel registration failed: {reason}"
        )));
    }

    // Initialize vardiff state if enabled.
    if config.vardiff_enabled
        && let Some(ch) = channels.get_mut(channel_id)
    {
        let initial_diff = shares::target_to_difficulty_u64(&config.channel_target);
        ch.vardiff = Some(crate::channels::VardiffState::new(
            initial_diff,
            config.vardiff_target_shares_per_min,
            config.vardiff_retarget_interval,
            config.vardiff_min_difficulty,
            config.vardiff_max_difficulty,
            config.vardiff_max_adjustment_factor,
        ));
    }

    // Register in global channel registry for HTTP /channels API.
    channel_registry
        .register(snapshot_from_open(
            channel_id,
            &open_req.user_identity,
            peer,
        ))
        .await;
    opened_ids.push(channel_id);

    debug!(
        peer = %peer_state.peer_addr,
        channel_id,
        worker = %open_req.user_identity,
        "standard mining channel opened",
    );

    // Send OpenStandardMiningChannel.Success.
    let success = sv2_codec::OpenStandardMiningChannelSuccess {
        request_id: open_req.request_id,
        channel_id,
        target: config.channel_target,
        extranonce_prefix: extranonce_for_reply.clone(),
        group_channel_id: 0,
    };
    let success_payload = success.encode().map_err(HandlerExit::CodecError)?;
    transport
        .write_frame(
            0x0000,
            MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL_SUCCESS,
            &success_payload,
        )
        .await
        .map_err(HandlerExit::TransportError)?;

    // Send SetTarget for this channel.
    let set_target = sv2_codec::SetTarget {
        channel_id,
        maximum_target: config.channel_target,
    };
    let set_target_payload = set_target.encode().map_err(HandlerExit::CodecError)?;
    transport
        .write_frame(0x8000, MESSAGE_TYPE_SET_TARGET, &set_target_payload)
        .await
        .map_err(HandlerExit::TransportError)?;

    // Send initial NewMiningJob if one is available (WP-6).
    if let Some(ref job) = *latest_job.read().await {
        // Compute per-channel merkle root using this channel's extranonce.
        let merkle_root = crate::jobs::compute_merkle_root(
            &job.coinbase_tx_prefix,
            &extranonce_for_reply,
            &job.coinbase_tx_suffix,
            &job.merkle_path,
        );
        let new_job = sv2_codec::NewMiningJob {
            channel_id,
            job_id: job.job_id,
            min_ntime: job.min_ntime,
            version: job.version,
            merkle_root,
        };
        let job_payload = new_job.encode().map_err(HandlerExit::CodecError)?;
        transport
            .write_frame(0x8000, MESSAGE_TYPE_NEW_MINING_JOB, &job_payload)
            .await
            .map_err(HandlerExit::TransportError)?;

        if let Some(ref ph) = job.prevhash_update {
            let set_prev = sv2_codec::SetNewPrevHash {
                channel_id,
                job_id: job.job_id,
                prev_hash: ph.prev_hash,
                min_ntime: ph.min_ntime,
                nbits: ph.nbits,
            };
            let ph_payload = set_prev.encode().map_err(HandlerExit::CodecError)?;
            transport
                .write_frame(0x8000, MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH, &ph_payload)
                .await
                .map_err(HandlerExit::TransportError)?;

            // Update channel state with prevhash tracking.
            if let Some(ch) = channels.get_mut(channel_id) {
                ch.record_prevhash_sent(job.job_id, ph.min_ntime);
            }
        }

        if let Some(ch) = channels.get_mut(channel_id) {
            ch.record_active_job_sent(job.job_id);
        }

        info!(
            peer = %peer_state.peer_addr,
            channel_id,
            job_id = job.job_id,
            "sent initial NewMiningJob on channel open",
        );
    }

    Ok(())
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
async fn handle_open_extended_channel(
    transport: &mut Sv2Transport,
    peer_state: &PeerState,
    channels: &mut ConnectionChannels,
    channel_id_alloc: &ChannelIdAllocator,
    extranonce_alloc: &ExtranonceAllocator,
    config: &HandlerConfig,
    latest_job: &Arc<tokio::sync::RwLock<Option<Arc<JobBroadcast>>>>,
    payload: &[u8],
    channel_registry: &SharedChannelRegistry,
    peer: SocketAddr,
    opened_ids: &mut Vec<u32>,
) -> Result<(), HandlerExit> {
    let open_req = match sv2_codec::OpenExtendedMiningChannel::decode(payload) {
        Ok(r) => r,
        Err(e) => {
            let err = sv2_codec::OpenMiningChannelError {
                request_id: 0,
                error_code: "unsupported-protocol".to_string(),
            };
            if let Ok(err_payload) = err.encode()
                && let Err(we) = transport
                    .write_frame(0x0000, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR, &err_payload)
                    .await
            {
                debug!(
                    error = %we,
                    "best-effort OpenMiningChannel.Error write failed",
                );
            }
            return Err(HandlerExit::CodecError(e));
        }
    };

    // Validate min_extranonce_size: must be 2..=8.
    if open_req.min_extranonce_size < 2 || open_req.min_extranonce_size > 8 {
        warn!(
            peer = %peer_state.peer_addr,
            min_extranonce_size = open_req.min_extranonce_size,
            "invalid min_extranonce_size; rejecting extended channel",
        );
        let err = sv2_codec::OpenMiningChannelError {
            request_id: open_req.request_id,
            error_code: "max-target-out-of-range".to_string(),
        };
        if let Ok(err_payload) = err.encode()
            && let Err(e) = transport
                .write_frame(0x0000, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR, &err_payload)
                .await
        {
            debug!(error = %e, "best-effort error write failed");
        }
        return Err(HandlerExit::SetupRejected(
            "min_extranonce_size out of range".to_string(),
        ));
    }

    // Allocate channel ID.
    let Some(channel_id) = channel_id_alloc.allocate() else {
        warn!(
            peer = %peer_state.peer_addr,
            "channel_id allocation exhausted; rejecting extended channel",
        );
        let err = sv2_codec::OpenMiningChannelError {
            request_id: open_req.request_id,
            error_code: "max-target-out-of-range".to_string(),
        };
        if let Ok(err_payload) = err.encode()
            && let Err(e) = transport
                .write_frame(0x0000, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR, &err_payload)
                .await
        {
            debug!(error = %e, "best-effort error write failed");
        }
        return Err(HandlerExit::SetupRejected(
            "channel_id allocator exhausted".to_string(),
        ));
    };

    // Allocate extranonce prefix.
    let Some(extranonce_prefix) = extranonce_alloc.allocate() else {
        warn!(
            peer = %peer_state.peer_addr,
            "extranonce allocation exhausted; rejecting extended channel",
        );
        let err = sv2_codec::OpenMiningChannelError {
            request_id: open_req.request_id,
            error_code: "max-target-out-of-range".to_string(),
        };
        if let Ok(err_payload) = err.encode()
            && let Err(e) = transport
                .write_frame(0x0000, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR, &err_payload)
                .await
        {
            debug!(error = %e, "best-effort error write failed");
        }
        return Err(HandlerExit::SetupRejected(
            "extranonce allocator exhausted".to_string(),
        ));
    };

    // Compute extranonce_size: pool prefix + miner portion.
    // Miner portion is at least min_extranonce_size, floored at 4.
    let prefix_len = config.extranonce_prefix_len;
    let miner_portion = usize::from(open_req.min_extranonce_size).max(4);
    let extranonce_size_usize = prefix_len + miner_portion;
    // SV2 extranonce_size is u16.
    #[allow(clippy::cast_possible_truncation)]
    let extranonce_size = extranonce_size_usize as u16;

    // Clone prefix for the success reply before moving into channel state.
    let prefix_for_reply = extranonce_prefix.clone();

    // Register in connection channels.
    if let Err(reason) = channels.open_extended_channel(
        channel_id,
        extranonce_prefix,
        open_req.user_identity.clone(),
        None,
        config.channel_target,
        config.max_shares_per_second_per_channel,
        open_req.min_extranonce_size,
        extranonce_size,
    ) {
        warn!(
            peer = %peer_state.peer_addr,
            reason = %reason,
            "channel registration failed; rejecting extended channel",
        );
        let err = sv2_codec::OpenMiningChannelError {
            request_id: open_req.request_id,
            error_code: "max-target-out-of-range".to_string(),
        };
        if let Ok(err_payload) = err.encode()
            && let Err(e) = transport
                .write_frame(0x0000, MESSAGE_TYPE_OPEN_MINING_CHANNEL_ERROR, &err_payload)
                .await
        {
            debug!(error = %e, "best-effort error write failed");
        }
        return Err(HandlerExit::SetupRejected(format!(
            "channel registration failed: {reason}"
        )));
    }

    // Initialize vardiff state if enabled.
    if config.vardiff_enabled
        && let Some(ch) = channels.get_mut(channel_id)
    {
        let initial_diff = shares::target_to_difficulty_u64(&config.channel_target);
        ch.vardiff = Some(crate::channels::VardiffState::new(
            initial_diff,
            config.vardiff_target_shares_per_min,
            config.vardiff_retarget_interval,
            config.vardiff_min_difficulty,
            config.vardiff_max_difficulty,
            config.vardiff_max_adjustment_factor,
        ));
    }

    // Register in global channel registry for HTTP /channels API.
    channel_registry
        .register(snapshot_from_open(
            channel_id,
            &open_req.user_identity,
            peer,
        ))
        .await;
    opened_ids.push(channel_id);

    debug!(
        peer = %peer_state.peer_addr,
        channel_id,
        worker = %open_req.user_identity,
        extranonce_size,
        "extended mining channel opened",
    );

    // Send OpenExtendedMiningChannel.Success.
    let success = sv2_codec::OpenExtendedMiningChannelSuccess {
        request_id: open_req.request_id,
        channel_id,
        target: config.channel_target,
        extranonce_size,
        extranonce_prefix: prefix_for_reply,
    };
    let success_payload = success.encode().map_err(HandlerExit::CodecError)?;
    transport
        .write_frame(
            0x0000,
            MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL_SUCCESS,
            &success_payload,
        )
        .await
        .map_err(HandlerExit::TransportError)?;

    // Send SetTarget for this channel.
    let set_target = sv2_codec::SetTarget {
        channel_id,
        maximum_target: config.channel_target,
    };
    let target_payload = set_target.encode().map_err(HandlerExit::CodecError)?;
    transport
        .write_frame(0x8000, MESSAGE_TYPE_SET_TARGET, &target_payload)
        .await
        .map_err(HandlerExit::TransportError)?;

    // Send initial NewExtendedMiningJob if one is available.
    if let Some(ref job) = *latest_job.read().await {
        let ext_job = sv2_codec::NewExtendedMiningJob {
            channel_id,
            job_id: job.job_id,
            min_ntime: job.min_ntime,
            version: job.version,
            version_rolling_allowed: true,
            merkle_path: job.merkle_path.clone(),
            coinbase_tx_prefix: job.coinbase_tx_prefix.clone(),
            coinbase_tx_suffix: job.coinbase_tx_suffix.clone(),
        };
        let job_payload = ext_job.encode().map_err(HandlerExit::CodecError)?;
        transport
            .write_frame(0x8000, MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB, &job_payload)
            .await
            .map_err(HandlerExit::TransportError)?;

        // Send SetNewPrevHash if this job carries one.
        if let Some(ref ph) = job.prevhash_update {
            let set_prev = sv2_codec::SetNewPrevHash {
                channel_id,
                job_id: job.job_id,
                prev_hash: ph.prev_hash,
                min_ntime: ph.min_ntime,
                nbits: ph.nbits,
            };
            let ph_payload = set_prev.encode().map_err(HandlerExit::CodecError)?;
            transport
                .write_frame(0x8000, MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH, &ph_payload)
                .await
                .map_err(HandlerExit::TransportError)?;

            if let Some(ch) = channels.get_mut(channel_id) {
                ch.record_prevhash_sent(job.job_id, ph.min_ntime);
            }
        }

        if let Some(ch) = channels.get_mut(channel_id) {
            ch.record_active_job_sent(job.job_id);
        }

        info!(
            peer = %peer_state.peer_addr,
            channel_id,
            job_id = job.job_id,
            "sent initial NewExtendedMiningJob on channel open",
        );
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────
// Stage 3: Steady-state miner frame dispatch
// ─────────────────────────────────────────────────────────────────────

enum FrameAction {
    Continue,
    Disconnect(HandlerExit),
}

/// Send a best-effort `CloseChannel` rejection for an extended channel
/// request. Returns `FrameAction::Disconnect` for steady-state dispatch.
async fn reject_extended_channel_action(transport: &mut Sv2Transport) -> FrameAction {
    FrameAction::Disconnect(reject_extended_channel_err(transport).await)
}

/// Send a best-effort `CloseChannel` rejection for an extended channel
/// request. Returns a `HandlerExit` for the setup phase.
async fn reject_extended_channel_err(transport: &mut Sv2Transport) -> HandlerExit {
    let close = sv2_codec::CloseChannel {
        channel_id: 0,
        reason_code: GatewayReason::ExtendedChannelUnsupported
            .as_str()
            .to_string(),
    };
    if let Ok(close_payload) = close.encode()
        && let Err(e) = transport
            .write_frame(0x8000, MESSAGE_TYPE_CLOSE_CHANNEL, &close_payload)
            .await
    {
        debug!(error = %e, "best-effort CloseChannel write failed");
    }
    HandlerExit::SetupRejected("extended channels not supported".to_string())
}

/// Handle a miner-initiated `CloseChannel`. Unregisters the channel and
/// disconnects if no channels remain open.
async fn handle_close_channel(
    peer_state: &PeerState,
    channels: &mut ConnectionChannels,
    channel_registry: &SharedChannelRegistry,
    payload: &[u8],
) -> FrameAction {
    match sv2_codec::CloseChannel::decode(payload) {
        Ok(close) => {
            debug!(
                peer = %peer_state.peer_addr,
                channel_id = close.channel_id,
                reason = %close.reason_code,
                "miner closed channel",
            );
            channels.close_channel(close.channel_id);
            channel_registry.unregister(close.channel_id).await;
            if channels.open_count() == 0 {
                info!(
                    peer = %peer_state.peer_addr,
                    "all channels closed; disconnecting",
                );
                return FrameAction::Disconnect(HandlerExit::Shutdown);
            }
            FrameAction::Continue
        }
        Err(e) => {
            warn!(
                peer = %peer_state.peer_addr,
                error = %e,
                "failed to decode CloseChannel; disconnecting",
            );
            FrameAction::Disconnect(HandlerExit::CodecError(e))
        }
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn handle_miner_frame(
    transport: &mut Sv2Transport,
    peer_state: &PeerState,
    channels: &mut ConnectionChannels,
    channel_id_alloc: &ChannelIdAllocator,
    extranonce_alloc: &ExtranonceAllocator,
    config: &HandlerConfig,
    job_table: &Arc<tokio::sync::RwLock<JobTable>>,
    latest_job: &Arc<tokio::sync::RwLock<Option<Arc<JobBroadcast>>>>,
    share_dedup: &mut ShareDedupSet,
    share_event_tx: &mpsc::Sender<ShareAcceptedEvent>,
    share_forward_tx: &mpsc::Sender<ShareSubmission>,
    header: &Sv2FrameHeader,
    payload: &[u8],
    channel_registry: &SharedChannelRegistry,
    peer: SocketAddr,
    opened_ids: &mut Vec<u32>,
    vardiff_retarget_up: &Counter,
    vardiff_retarget_down: &Counter,
) -> FrameAction {
    // Reject non-base-protocol extension types.
    if header.extension_type & 0x7FFF != 0 {
        warn!(
            peer = %peer_state.peer_addr,
            extension_type = header.extension_type,
            "unsupported extension_type in steady-state frame; disconnecting",
        );
        return FrameAction::Disconnect(HandlerExit::SetupRejected(format!(
            "unsupported extension_type 0x{:04x}",
            header.extension_type,
        )));
    }

    match header.msg_type {
        MESSAGE_TYPE_SUBMIT_SHARES_STANDARD => {
            match handle_submit_shares(
                transport,
                peer_state,
                channels,
                config,
                job_table,
                share_dedup,
                share_event_tx,
                share_forward_tx,
                payload,
                vardiff_retarget_up,
                vardiff_retarget_down,
            )
            .await
            {
                Ok(()) => FrameAction::Continue,
                Err(exit) => FrameAction::Disconnect(exit),
            }
        }
        MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED => {
            match handle_submit_shares_extended(
                transport,
                peer_state,
                channels,
                config,
                job_table,
                share_dedup,
                share_event_tx,
                share_forward_tx,
                payload,
                vardiff_retarget_up,
                vardiff_retarget_down,
            )
            .await
            {
                Ok(()) => FrameAction::Continue,
                Err(exit) => FrameAction::Disconnect(exit),
            }
        }
        MESSAGE_TYPE_OPEN_STANDARD_MINING_CHANNEL => {
            // Additional channel open on existing connection.
            match handle_open_standard_channel(
                transport,
                peer_state,
                channels,
                channel_id_alloc,
                extranonce_alloc,
                config,
                latest_job,
                payload,
                channel_registry,
                peer,
                opened_ids,
            )
            .await
            {
                Ok(()) => FrameAction::Continue,
                Err(exit) => FrameAction::Disconnect(exit),
            }
        }
        MESSAGE_TYPE_OPEN_EXTENDED_MINING_CHANNEL => {
            if !config.extended_channels_enabled {
                return reject_extended_channel_action(transport).await;
            }
            match handle_open_extended_channel(
                transport,
                peer_state,
                channels,
                channel_id_alloc,
                extranonce_alloc,
                config,
                latest_job,
                payload,
                channel_registry,
                peer,
                opened_ids,
            )
            .await
            {
                Ok(()) => FrameAction::Continue,
                Err(exit) => FrameAction::Disconnect(exit),
            }
        }
        MESSAGE_TYPE_CLOSE_CHANNEL => {
            handle_close_channel(peer_state, channels, channel_registry, payload).await
        }
        other => {
            debug!(
                peer = %peer_state.peer_addr,
                msg_type = other,
                "unhandled message type; ignoring",
            );
            FrameAction::Continue
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Share submission
// ─────────────────────────────────────────────────────────────────────

#[allow(
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::cast_precision_loss
)]
async fn handle_submit_shares(
    transport: &mut Sv2Transport,
    peer_state: &PeerState,
    channels: &mut ConnectionChannels,
    config: &HandlerConfig,
    job_table: &Arc<tokio::sync::RwLock<JobTable>>,
    share_dedup: &mut ShareDedupSet,
    share_event_tx: &mpsc::Sender<ShareAcceptedEvent>,
    share_forward_tx: &mpsc::Sender<ShareSubmission>,
    payload: &[u8],
    vardiff_retarget_up: &Counter,
    vardiff_retarget_down: &Counter,
) -> Result<(), HandlerExit> {
    let share = match sv2_codec::SubmitSharesStandard::decode(payload) {
        Ok(s) => s,
        Err(e) => {
            // Best effort: send SubmitShares.Error with zeroed IDs since the
            // decode failed and we cannot extract channel_id or sequence_number.
            let err = sv2_codec::SubmitSharesError {
                channel_id: 0,
                sequence_number: 0,
                error_code: GatewayReason::FrameDecodeError
                    .to_sv2_error_code()
                    .to_string(),
            };
            if let Ok(err_payload) = err.encode()
                && let Err(we) = transport
                    .write_frame(0x8000, MESSAGE_TYPE_SUBMIT_SHARES_ERROR, &err_payload)
                    .await
            {
                debug!(error = %we, "best-effort SubmitShares.Error write failed");
            }
            return Err(HandlerExit::CodecError(e));
        }
    };

    // ── Step 0: Validate channel exists ──
    let Some(_channel) = channels.get(share.channel_id) else {
        let evt = ShareAcceptedEvent::sentinel(
            &GatewayReason::InvalidChannelId,
            share.channel_id,
            share.sequence_number,
            share.job_id,
        );
        if let Err(e) = share_event_tx.try_send(evt) {
            warn!(error = %e, "share_event_tx full; share event dropped");
        }
        return send_share_error(
            transport,
            share.channel_id,
            share.sequence_number,
            GatewayReason::InvalidChannelId,
        )
        .await;
    };

    // ── Step 0.5: Per-channel share rate limit ──
    // Use get_mut to update the token bucket. The borrow is released
    // immediately after the check so subsequent immutable reads work.
    if let Some(ch) = channels.get_mut(share.channel_id)
        && !ch.rate_limiter.try_acquire()
    {
        warn!(
            peer = %peer_state.peer_addr,
            channel_id = share.channel_id,
            "share rejected: per-channel rate limit exceeded",
        );
        let evt = ShareAcceptedEvent::sentinel(
            &GatewayReason::ShareRateLimited,
            share.channel_id,
            share.sequence_number,
            share.job_id,
        );
        if let Err(e) = share_event_tx.try_send(evt) {
            warn!(error = %e, "share_event_tx full; share event dropped");
        }
        return send_share_error(
            transport,
            share.channel_id,
            share.sequence_number,
            GatewayReason::ShareRateLimited,
        )
        .await;
    }

    // Re-acquire immutable borrow after rate limiter mutation.
    // Channel cannot disappear between step 0 and step 0.5 because
    // we hold the only mutable reference to ConnectionChannels and
    // close_channel is not called in between. The unwrap_or_else
    // with InvalidChannelId covers any impossible edge case.
    let Some(channel) = channels.get(share.channel_id) else {
        return send_share_error(
            transport,
            share.channel_id,
            share.sequence_number,
            GatewayReason::InvalidChannelId,
        )
        .await;
    };

    // Snapshot channel state before releasing the borrow.
    let channel_target = channel.maximum_target;
    let channel_extranonce = channel.extranonce_prefix.clone();
    let activation_min_ntime = channel.activation_min_ntime;
    let elapsed_secs = channel.elapsed_since_prevhash_secs();
    let worker_id = channel.worker_id.clone();

    // ── Step 1: Validate job_id is in job table ──
    let table = job_table.read().await;
    let Some(job) = table.get(share.job_id) else {
        drop(table);
        let evt = ShareAcceptedEvent::sentinel(
            &GatewayReason::ShareInvalidJobId,
            share.channel_id,
            share.sequence_number,
            share.job_id,
        );
        if let Err(e) = share_event_tx.try_send(evt) {
            warn!(error = %e, "share_event_tx full; share event dropped");
        }
        return send_share_error(
            transport,
            share.channel_id,
            share.sequence_number,
            GatewayReason::ShareInvalidJobId,
        )
        .await;
    };

    // Snapshot job fields we need for validation.
    let job_version = job.version;
    let job_prev_hash = job.prev_hash;
    let job_nbits = job.nbits;
    let job_activation_min_ntime = job.activation_min_ntime;
    let job_block_height = job.block_height;
    let job_coinbase_prefix = job.coinbase_tx_prefix.clone();
    let job_coinbase_suffix = job.coinbase_tx_suffix.clone();
    let job_merkle_path = job.merkle_path.clone();
    let job_template_id = job.template_id;
    let job_source_instance_id = job.source_instance_id.clone();
    drop(table);

    // ── Step 2: Validate version bits (BIP 320) ──
    if !check_version_bits(share.version, job_version) {
        warn!(
            peer = %peer_state.peer_addr,
            channel_id = share.channel_id,
            share_version = share.version,
            job_version,
            "share rejected: version bit violation",
        );
        let evt = ShareAcceptedEvent::sentinel(
            &GatewayReason::VersionBitViolation,
            share.channel_id,
            share.sequence_number,
            share.job_id,
        );
        if let Err(e) = share_event_tx.try_send(evt) {
            warn!(error = %e, "share_event_tx full; share event dropped");
        }
        return send_share_error(
            transport,
            share.channel_id,
            share.sequence_number,
            GatewayReason::VersionBitViolation,
        )
        .await;
    }

    // ── Step 3: Validate ntime bounds ──
    let effective_min_ntime = activation_min_ntime.unwrap_or(job_activation_min_ntime);
    let effective_elapsed = elapsed_secs.unwrap_or(0);
    let now_unix = current_unix_timestamp();

    if !check_ntime_bounds(
        share.ntime,
        effective_min_ntime,
        effective_elapsed,
        config.ntime_elapsed_slack_seconds,
        config.max_future_block_time_seconds,
        now_unix,
    ) {
        warn!(
            peer = %peer_state.peer_addr,
            channel_id = share.channel_id,
            ntime = share.ntime,
            min_ntime = effective_min_ntime,
            elapsed = effective_elapsed,
            "share rejected: ntime out of range",
        );
        let evt = ShareAcceptedEvent::sentinel(
            &GatewayReason::NtimeOutOfRange,
            share.channel_id,
            share.sequence_number,
            share.job_id,
        );
        if let Err(e) = share_event_tx.try_send(evt) {
            warn!(error = %e, "share_event_tx full; share event dropped");
        }
        return send_share_error(
            transport,
            share.channel_id,
            share.sequence_number,
            GatewayReason::NtimeOutOfRange,
        )
        .await;
    }

    // ── Step 4: Build 80-byte header and validate PoW ──
    let merkle_root = crate::jobs::compute_merkle_root(
        &job_coinbase_prefix,
        &channel_extranonce,
        &job_coinbase_suffix,
        &job_merkle_path,
    );

    let header_bytes = header_identity_bytes(
        share.version,
        &job_prev_hash,
        &merkle_root,
        share.ntime,
        job_nbits,
        share.nonce,
    );

    if !validate_share_pow(&header_bytes, &channel_target) {
        debug!(
            peer = %peer_state.peer_addr,
            channel_id = share.channel_id,
            "share rejected: difficulty below target",
        );
        // PoW failed but we can still compute share_id for the event.
        let sid = compute_share_id(&header_bytes);
        let eid = compute_event_id(&sid, &worker_id, "full");
        let evt = ShareAcceptedEvent {
            event_type: "share_accepted",
            share_id_hex: hex::encode(sid),
            event_id_hex: hex::encode(eid),
            sv2_response: "error",
            reason_code: Some(
                GatewayReason::ShareDifficultyBelowTarget
                    .as_str()
                    .to_string(),
            ),
            reason_detail: Some(GatewayReason::ShareDifficultyBelowTarget.to_string()),
            worker_id: worker_id.clone(),
            channel_id: share.channel_id,
            sequence_number: share.sequence_number,
            job_id: share.job_id,
            block_height: job_block_height,
            timestamp_ms: unix_ms_now(),
            difficulty_u64: 0,
        };
        if let Err(e) = share_event_tx.try_send(evt) {
            warn!(error = %e, "share_event_tx full; share event dropped");
        }
        return send_share_error(
            transport,
            share.channel_id,
            share.sequence_number,
            GatewayReason::ShareDifficultyBelowTarget,
        )
        .await;
    }

    // ── Step 5: Replay detection ──
    let share_id = compute_share_id(&header_bytes);
    if share_dedup.check_and_insert(&share_id) {
        warn!(
            peer = %peer_state.peer_addr,
            channel_id = share.channel_id,
            share_id_hex = hex::encode(share_id),
            "share rejected: replay detected",
        );
        let eid = compute_event_id(&share_id, &worker_id, "full");
        let evt = ShareAcceptedEvent {
            event_type: "share_accepted",
            share_id_hex: hex::encode(share_id),
            event_id_hex: hex::encode(eid),
            sv2_response: "error",
            reason_code: Some(GatewayReason::ShareReplayDetected.as_str().to_string()),
            reason_detail: Some(GatewayReason::ShareReplayDetected.to_string()),
            worker_id: worker_id.clone(),
            channel_id: share.channel_id,
            sequence_number: share.sequence_number,
            job_id: share.job_id,
            block_height: job_block_height,
            timestamp_ms: unix_ms_now(),
            difficulty_u64: 0,
        };
        if let Err(e) = share_event_tx.try_send(evt) {
            warn!(error = %e, "share_event_tx full; share event dropped");
        }
        return send_share_error(
            transport,
            share.channel_id,
            share.sequence_number,
            GatewayReason::ShareReplayDetected,
        )
        .await;
    }

    // ── Share accepted ──
    peer_state.record_frame_decoded();

    let difficulty = shares::target_to_difficulty_u64(&channel_target);
    let share_id_hex = hex::encode(share_id);
    let event_id = compute_event_id(&share_id, &worker_id, "full");
    let event_id_hex = hex::encode(event_id);

    debug!(
        peer = %peer_state.peer_addr,
        channel_id = share.channel_id,
        job_id = share.job_id,
        seq = share.sequence_number,
        difficulty,
        share_id_hex = %share_id_hex,
        "share accepted",
    );

    // Enqueue for upstream relay.
    let prev_hash_wire = job_prev_hash;
    let mut prev_hash_display = job_prev_hash;
    prev_hash_display.reverse();

    let mut merkle_root_display = merkle_root;
    merkle_root_display.reverse();

    let mut submission = ShareSubmission {
        share_id_hex: share_id_hex.clone(),
        version: share.version,
        prev_hash_wire_hex: hex::encode(prev_hash_wire),
        prev_hash_display_hex: hex::encode(prev_hash_display),
        merkle_root_wire_hex: hex::encode(merkle_root),
        merkle_root_display_hex: hex::encode(merkle_root_display),
        ntime: share.ntime,
        nbits: job_nbits,
        nonce: share.nonce,
        event_id_hex: event_id_hex.clone(),
        worker_id: worker_id.clone(),
        validation_level: "full".to_string(),
        gateway_instance_id: config.gateway_instance_id.clone(),
        channel_id: share.channel_id,
        sequence_number: share.sequence_number,
        job_id: share.job_id,
        template_id: job_template_id,
        block_height: job_block_height,
        pool_account_id: None,
        timestamp_ms: unix_ms_now(),
        difficulty_u64: difficulty,
        difficulty_display: difficulty as f64,
        source_instance_id: job_source_instance_id,
        gateway_signature_hex: String::new(),
    };
    {
        let secret = config.share_hmac_secret.read().unwrap_or_else(|e| {
            warn!("share_hmac_secret lock poisoned, signing disabled: {e}");
            e.into_inner()
        });
        sign_submission(&secret, &mut submission);
    }
    // PB-38: a share dropped here is a share upstream never receives, and
    // this is the pool's accounting path. Reporting Success would credit the
    // miner for work that was thrown away. `ShareDroppedQueueFull` already
    // carries an SV2 wire code ("stale-share") and is deliberately NOT in the
    // post-ACK telemetry group that `to_sv2_error_code` calls unreachable! on,
    // because enqueue failure happens BEFORE the ACK and the miner can still
    // be told the truth. Eviction, which happens after, cannot be.
    if let Err(e) = share_forward_tx.try_send(submission) {
        warn!(
            error = %e,
            reason_code = GatewayReason::ShareDroppedQueueFull.as_str(),
            channel_id = share.channel_id,
            sequence_number = share.sequence_number,
            "share_forward_tx full; share dropped and REJECTED to the miner",
        );
        // The accounting stream must agree with what the miner was told.
        // Every other rejection in this function emits an error event, and the
        // success event below now fires ONLY on a successful enqueue, so a
        // dropped share is no longer credited in shares_total, in the channel
        // registry's shares_accepted, or as a WAL pending record that no
        // forward result will ever complete.
        let evt = ShareAcceptedEvent {
            event_type: "share_accepted",
            share_id_hex: share_id_hex.clone(),
            event_id_hex: event_id_hex.clone(),
            sv2_response: "error",
            reason_code: Some(GatewayReason::ShareDroppedQueueFull.as_str().to_string()),
            reason_detail: Some(GatewayReason::ShareDroppedQueueFull.to_string()),
            worker_id: worker_id.clone(),
            channel_id: share.channel_id,
            sequence_number: share.sequence_number,
            job_id: share.job_id,
            block_height: job_block_height,
            timestamp_ms: unix_ms_now(),
            difficulty_u64: 0,
        };
        if let Err(e) = share_event_tx.try_send(evt) {
            warn!(error = %e, "share_event_tx full; share event dropped");
        }
        return send_share_error(
            transport,
            share.channel_id,
            share.sequence_number,
            GatewayReason::ShareDroppedQueueFull,
        )
        .await;
    }

    // Emitted ONLY after the share is safely queued for relay (PB-38).
    let evt = ShareAcceptedEvent {
        event_type: "share_accepted",
        share_id_hex: share_id_hex.clone(),
        event_id_hex: event_id_hex.clone(),
        sv2_response: "success",
        reason_code: None,
        reason_detail: None,
        worker_id: worker_id.clone(),
        channel_id: share.channel_id,
        sequence_number: share.sequence_number,
        job_id: share.job_id,
        block_height: job_block_height,
        timestamp_ms: unix_ms_now(),
        difficulty_u64: difficulty,
    };
    if let Err(e) = share_event_tx.try_send(evt) {
        warn!(error = %e, "share_event_tx full; share event dropped");
    }

    let success = sv2_codec::SubmitSharesSuccess {
        channel_id: share.channel_id,
        last_sequence_number: share.sequence_number,
        new_submits_accepted_count: 1,
        new_shares_sum: difficulty,
    };
    let success_payload = success.encode().map_err(HandlerExit::CodecError)?;
    transport
        .write_frame(0x8000, MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS, &success_payload)
        .await
        .map_err(HandlerExit::TransportError)?;

    // Vardiff retarget check.
    maybe_retarget(
        transport,
        channels,
        share.channel_id,
        vardiff_retarget_up,
        vardiff_retarget_down,
    )
    .await?;

    Ok(())
}

/// Send a `SubmitShares.Error` response with the appropriate SV2 wire code.
async fn send_share_error(
    transport: &mut Sv2Transport,
    channel_id: u32,
    sequence_number: u32,
    reason: GatewayReason,
) -> Result<(), HandlerExit> {
    let err = sv2_codec::SubmitSharesError {
        channel_id,
        sequence_number,
        error_code: reason.to_sv2_error_code().to_string(),
    };
    let err_payload = err.encode().map_err(HandlerExit::CodecError)?;
    transport
        .write_frame(0x8000, MESSAGE_TYPE_SUBMIT_SHARES_ERROR, &err_payload)
        .await
        .map_err(HandlerExit::TransportError)?;
    Ok(())
}

/// Handle `SubmitSharesExtended` (0x1b). Extended shares include a
/// miner-provided extranonce that is concatenated with the channel's
/// pool-assigned prefix to form the full extranonce for coinbase assembly.
/// The rest of the validation pipeline is identical to standard shares.
#[allow(
    clippy::too_many_lines,
    clippy::too_many_arguments,
    clippy::cast_precision_loss
)]
async fn handle_submit_shares_extended(
    transport: &mut Sv2Transport,
    peer_state: &PeerState,
    channels: &mut ConnectionChannels,
    config: &HandlerConfig,
    job_table: &Arc<tokio::sync::RwLock<JobTable>>,
    share_dedup: &mut ShareDedupSet,
    share_event_tx: &mpsc::Sender<ShareAcceptedEvent>,
    share_forward_tx: &mpsc::Sender<ShareSubmission>,
    payload: &[u8],
    vardiff_retarget_up: &Counter,
    vardiff_retarget_down: &Counter,
) -> Result<(), HandlerExit> {
    let share = match sv2_codec::SubmitSharesExtended::decode(payload) {
        Ok(s) => s,
        Err(e) => {
            let err = sv2_codec::SubmitSharesError {
                channel_id: 0,
                sequence_number: 0,
                error_code: GatewayReason::FrameDecodeError
                    .to_sv2_error_code()
                    .to_string(),
            };
            if let Ok(err_payload) = err.encode()
                && let Err(we) = transport
                    .write_frame(0x8000, MESSAGE_TYPE_SUBMIT_SHARES_ERROR, &err_payload)
                    .await
            {
                debug!(
                    error = %we,
                    "best-effort SubmitShares.Error write failed",
                );
            }
            return Err(HandlerExit::CodecError(e));
        }
    };

    // ── Step 0: Validate channel exists ──
    let Some(_channel) = channels.get(share.channel_id) else {
        let evt = ShareAcceptedEvent::sentinel(
            &GatewayReason::InvalidChannelId,
            share.channel_id,
            share.sequence_number,
            share.job_id,
        );
        if let Err(e) = share_event_tx.try_send(evt) {
            warn!(error = %e, "share_event_tx full; share event dropped");
        }
        return send_share_error(
            transport,
            share.channel_id,
            share.sequence_number,
            GatewayReason::InvalidChannelId,
        )
        .await;
    };

    // ── Step 0.5: Per-channel share rate limit ──
    if let Some(ch) = channels.get_mut(share.channel_id)
        && !ch.rate_limiter.try_acquire()
    {
        warn!(
            peer = %peer_state.peer_addr,
            channel_id = share.channel_id,
            "share rejected: per-channel rate limit exceeded",
        );
        let evt = ShareAcceptedEvent::sentinel(
            &GatewayReason::ShareRateLimited,
            share.channel_id,
            share.sequence_number,
            share.job_id,
        );
        if let Err(e) = share_event_tx.try_send(evt) {
            warn!(error = %e, "share_event_tx full; share event dropped");
        }
        return send_share_error(
            transport,
            share.channel_id,
            share.sequence_number,
            GatewayReason::ShareRateLimited,
        )
        .await;
    }

    // Re-acquire immutable borrow.
    let Some(channel) = channels.get(share.channel_id) else {
        return send_share_error(
            transport,
            share.channel_id,
            share.sequence_number,
            GatewayReason::InvalidChannelId,
        )
        .await;
    };

    // ── Step 0.75: Validate channel is extended and extranonce length ──
    let expected_miner_en_len = match channel.kind {
        ChannelKind::Extended {
            extranonce_size, ..
        } => usize::from(extranonce_size) - channel.extranonce_prefix.len(),
        ChannelKind::Standard => {
            warn!(
                peer = %peer_state.peer_addr,
                channel_id = share.channel_id,
                "SubmitSharesExtended on standard channel; rejecting",
            );
            return send_share_error(
                transport,
                share.channel_id,
                share.sequence_number,
                GatewayReason::InvalidChannelId,
            )
            .await;
        }
    };

    if share.extranonce.len() != expected_miner_en_len {
        warn!(
            peer = %peer_state.peer_addr,
            channel_id = share.channel_id,
            got = share.extranonce.len(),
            expected = expected_miner_en_len,
            "extranonce length mismatch; rejecting share",
        );
        return send_share_error(
            transport,
            share.channel_id,
            share.sequence_number,
            GatewayReason::ShareInvalidNonce,
        )
        .await;
    }

    // Construct full extranonce: pool_prefix || miner_extranonce.
    let mut full_extranonce = channel.extranonce_prefix.clone();
    full_extranonce.extend_from_slice(&share.extranonce);

    // Snapshot channel state.
    let channel_target = channel.maximum_target;
    let activation_min_ntime = channel.activation_min_ntime;
    let elapsed_secs = channel.elapsed_since_prevhash_secs();
    let worker_id = channel.worker_id.clone();

    // ── Step 1: Validate job_id ──
    let table = job_table.read().await;
    let Some(job) = table.get(share.job_id) else {
        drop(table);
        let evt = ShareAcceptedEvent::sentinel(
            &GatewayReason::ShareInvalidJobId,
            share.channel_id,
            share.sequence_number,
            share.job_id,
        );
        if let Err(e) = share_event_tx.try_send(evt) {
            warn!(error = %e, "share_event_tx full; share event dropped");
        }
        return send_share_error(
            transport,
            share.channel_id,
            share.sequence_number,
            GatewayReason::ShareInvalidJobId,
        )
        .await;
    };

    let job_version = job.version;
    let job_prev_hash = job.prev_hash;
    let job_nbits = job.nbits;
    let job_activation_min_ntime = job.activation_min_ntime;
    let job_block_height = job.block_height;
    let job_coinbase_prefix = job.coinbase_tx_prefix.clone();
    let job_coinbase_suffix = job.coinbase_tx_suffix.clone();
    let job_merkle_path = job.merkle_path.clone();
    let job_template_id = job.template_id;
    let job_source_instance_id = job.source_instance_id.clone();
    drop(table);

    // ── Step 2: Validate version bits (BIP 320) ──
    if !check_version_bits(share.version, job_version) {
        warn!(
            peer = %peer_state.peer_addr,
            channel_id = share.channel_id,
            share_version = share.version,
            job_version,
            "share rejected: version bit violation",
        );
        let evt = ShareAcceptedEvent::sentinel(
            &GatewayReason::VersionBitViolation,
            share.channel_id,
            share.sequence_number,
            share.job_id,
        );
        if let Err(e) = share_event_tx.try_send(evt) {
            warn!(error = %e, "share_event_tx full; share event dropped");
        }
        return send_share_error(
            transport,
            share.channel_id,
            share.sequence_number,
            GatewayReason::VersionBitViolation,
        )
        .await;
    }

    // ── Step 3: Validate ntime bounds ──
    let effective_min_ntime = activation_min_ntime.unwrap_or(job_activation_min_ntime);
    let effective_elapsed = elapsed_secs.unwrap_or(0);
    let now_unix = current_unix_timestamp();

    if !check_ntime_bounds(
        share.ntime,
        effective_min_ntime,
        effective_elapsed,
        config.ntime_elapsed_slack_seconds,
        config.max_future_block_time_seconds,
        now_unix,
    ) {
        warn!(
            peer = %peer_state.peer_addr,
            channel_id = share.channel_id,
            ntime = share.ntime,
            "share rejected: ntime out of range",
        );
        let evt = ShareAcceptedEvent::sentinel(
            &GatewayReason::NtimeOutOfRange,
            share.channel_id,
            share.sequence_number,
            share.job_id,
        );
        if let Err(e) = share_event_tx.try_send(evt) {
            warn!(error = %e, "share_event_tx full; share event dropped");
        }
        return send_share_error(
            transport,
            share.channel_id,
            share.sequence_number,
            GatewayReason::NtimeOutOfRange,
        )
        .await;
    }

    // ── Step 4: Build 80-byte header and validate PoW ──
    // Extended shares use pool_prefix || miner_extranonce as the
    // full extranonce in coinbase assembly.
    let merkle_root = crate::jobs::compute_merkle_root(
        &job_coinbase_prefix,
        &full_extranonce,
        &job_coinbase_suffix,
        &job_merkle_path,
    );

    let header_bytes = header_identity_bytes(
        share.version,
        &job_prev_hash,
        &merkle_root,
        share.ntime,
        job_nbits,
        share.nonce,
    );

    if !validate_share_pow(&header_bytes, &channel_target) {
        debug!(
            peer = %peer_state.peer_addr,
            channel_id = share.channel_id,
            "share rejected: difficulty below target",
        );
        let sid = compute_share_id(&header_bytes);
        let eid = compute_event_id(&sid, &worker_id, "full");
        let evt = ShareAcceptedEvent {
            event_type: "share_accepted",
            share_id_hex: hex::encode(sid),
            event_id_hex: hex::encode(eid),
            sv2_response: "error",
            reason_code: Some(
                GatewayReason::ShareDifficultyBelowTarget
                    .as_str()
                    .to_string(),
            ),
            reason_detail: Some(GatewayReason::ShareDifficultyBelowTarget.to_string()),
            worker_id: worker_id.clone(),
            channel_id: share.channel_id,
            sequence_number: share.sequence_number,
            job_id: share.job_id,
            block_height: job_block_height,
            timestamp_ms: unix_ms_now(),
            difficulty_u64: 0,
        };
        if let Err(e) = share_event_tx.try_send(evt) {
            warn!(error = %e, "share_event_tx full; share event dropped");
        }
        return send_share_error(
            transport,
            share.channel_id,
            share.sequence_number,
            GatewayReason::ShareDifficultyBelowTarget,
        )
        .await;
    }

    // ── Step 5: Replay detection ──
    let share_id = compute_share_id(&header_bytes);
    if share_dedup.check_and_insert(&share_id) {
        warn!(
            peer = %peer_state.peer_addr,
            channel_id = share.channel_id,
            share_id_hex = hex::encode(share_id),
            "share rejected: replay detected",
        );
        let eid = compute_event_id(&share_id, &worker_id, "full");
        let evt = ShareAcceptedEvent {
            event_type: "share_accepted",
            share_id_hex: hex::encode(share_id),
            event_id_hex: hex::encode(eid),
            sv2_response: "error",
            reason_code: Some(GatewayReason::ShareReplayDetected.as_str().to_string()),
            reason_detail: Some(GatewayReason::ShareReplayDetected.to_string()),
            worker_id: worker_id.clone(),
            channel_id: share.channel_id,
            sequence_number: share.sequence_number,
            job_id: share.job_id,
            block_height: job_block_height,
            timestamp_ms: unix_ms_now(),
            difficulty_u64: 0,
        };
        if let Err(e) = share_event_tx.try_send(evt) {
            warn!(error = %e, "share_event_tx full; share event dropped");
        }
        return send_share_error(
            transport,
            share.channel_id,
            share.sequence_number,
            GatewayReason::ShareReplayDetected,
        )
        .await;
    }

    // ── Share accepted ──
    peer_state.record_frame_decoded();

    let difficulty = shares::target_to_difficulty_u64(&channel_target);
    let share_id_hex = hex::encode(share_id);
    let event_id = compute_event_id(&share_id, &worker_id, "full");
    let event_id_hex = hex::encode(event_id);

    debug!(
        peer = %peer_state.peer_addr,
        channel_id = share.channel_id,
        job_id = share.job_id,
        seq = share.sequence_number,
        difficulty,
        share_id_hex = %share_id_hex,
        extranonce_hex = %hex::encode(&full_extranonce),
        "extended share accepted",
    );

    // Enqueue for upstream relay.
    let prev_hash_wire = job_prev_hash;
    let mut prev_hash_display = job_prev_hash;
    prev_hash_display.reverse();

    let mut merkle_root_display = merkle_root;
    merkle_root_display.reverse();

    let mut submission = ShareSubmission {
        share_id_hex: share_id_hex.clone(),
        version: share.version,
        prev_hash_wire_hex: hex::encode(prev_hash_wire),
        prev_hash_display_hex: hex::encode(prev_hash_display),
        merkle_root_wire_hex: hex::encode(merkle_root),
        merkle_root_display_hex: hex::encode(merkle_root_display),
        ntime: share.ntime,
        nbits: job_nbits,
        nonce: share.nonce,
        event_id_hex: event_id_hex.clone(),
        worker_id: worker_id.clone(),
        validation_level: "full".to_string(),
        gateway_instance_id: config.gateway_instance_id.clone(),
        channel_id: share.channel_id,
        sequence_number: share.sequence_number,
        job_id: share.job_id,
        template_id: job_template_id,
        block_height: job_block_height,
        pool_account_id: None,
        timestamp_ms: unix_ms_now(),
        difficulty_u64: difficulty,
        difficulty_display: difficulty as f64,
        source_instance_id: job_source_instance_id,
        gateway_signature_hex: String::new(),
    };
    {
        let secret = config.share_hmac_secret.read().unwrap_or_else(|e| {
            warn!("share_hmac_secret lock poisoned, signing disabled: {e}");
            e.into_inner()
        });
        sign_submission(&secret, &mut submission);
    }
    // PB-38: identical to the standard path. See the comment there.
    if let Err(e) = share_forward_tx.try_send(submission) {
        warn!(
            error = %e,
            reason_code = GatewayReason::ShareDroppedQueueFull.as_str(),
            channel_id = share.channel_id,
            sequence_number = share.sequence_number,
            "share_forward_tx full; share dropped and REJECTED to the miner",
        );
        // The accounting stream must agree with what the miner was told.
        // Every other rejection in this function emits an error event, and the
        // success event below now fires ONLY on a successful enqueue, so a
        // dropped share is no longer credited in shares_total, in the channel
        // registry's shares_accepted, or as a WAL pending record that no
        // forward result will ever complete.
        let evt = ShareAcceptedEvent {
            event_type: "share_accepted",
            share_id_hex: share_id_hex.clone(),
            event_id_hex: event_id_hex.clone(),
            sv2_response: "error",
            reason_code: Some(GatewayReason::ShareDroppedQueueFull.as_str().to_string()),
            reason_detail: Some(GatewayReason::ShareDroppedQueueFull.to_string()),
            worker_id: worker_id.clone(),
            channel_id: share.channel_id,
            sequence_number: share.sequence_number,
            job_id: share.job_id,
            block_height: job_block_height,
            timestamp_ms: unix_ms_now(),
            difficulty_u64: 0,
        };
        if let Err(e) = share_event_tx.try_send(evt) {
            warn!(error = %e, "share_event_tx full; share event dropped");
        }
        return send_share_error(
            transport,
            share.channel_id,
            share.sequence_number,
            GatewayReason::ShareDroppedQueueFull,
        )
        .await;
    }

    // Emitted ONLY after the share is safely queued for relay (PB-38).
    let evt = ShareAcceptedEvent {
        event_type: "share_accepted",
        share_id_hex: share_id_hex.clone(),
        event_id_hex: event_id_hex.clone(),
        sv2_response: "success",
        reason_code: None,
        reason_detail: None,
        worker_id: worker_id.clone(),
        channel_id: share.channel_id,
        sequence_number: share.sequence_number,
        job_id: share.job_id,
        block_height: job_block_height,
        timestamp_ms: unix_ms_now(),
        difficulty_u64: difficulty,
    };
    if let Err(e) = share_event_tx.try_send(evt) {
        warn!(error = %e, "share_event_tx full; share event dropped");
    }

    let success = sv2_codec::SubmitSharesSuccess {
        channel_id: share.channel_id,
        last_sequence_number: share.sequence_number,
        new_submits_accepted_count: 1,
        new_shares_sum: difficulty,
    };
    let success_payload = success.encode().map_err(HandlerExit::CodecError)?;
    transport
        .write_frame(0x8000, MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS, &success_payload)
        .await
        .map_err(HandlerExit::TransportError)?;

    // Vardiff retarget check.
    maybe_retarget(
        transport,
        channels,
        share.channel_id,
        vardiff_retarget_up,
        vardiff_retarget_down,
    )
    .await?;

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────
// Vardiff retarget
// ─────────────────────────────────────────────────────────────────────

/// Check whether the channel's vardiff state warrants a retarget. If the
/// retarget interval has elapsed and the new difficulty differs, send a
/// `SetTarget` message updating the channel's `maximum_target`.
async fn maybe_retarget(
    transport: &mut Sv2Transport,
    channels: &mut ConnectionChannels,
    channel_id: u32,
    retarget_up: &Counter,
    retarget_down: &Counter,
) -> Result<(), HandlerExit> {
    let Some(ch) = channels.get_mut(channel_id) else {
        return Ok(());
    };
    let Some(ref mut vd) = ch.vardiff else {
        return Ok(());
    };
    let old_diff = vd.current_difficulty;
    if !vd.record_share() {
        return Ok(());
    }
    let Some(new_diff) = vd.evaluate_retarget() else {
        return Ok(());
    };

    let new_target = shares::difficulty_to_target(new_diff);
    ch.maximum_target = new_target;

    if new_diff > old_diff {
        retarget_up.inc();
    } else {
        retarget_down.inc();
    }

    info!(channel_id, new_difficulty = new_diff, "vardiff retarget",);

    let set_target = sv2_codec::SetTarget {
        channel_id,
        maximum_target: new_target,
    };
    let target_payload = set_target.encode().map_err(HandlerExit::CodecError)?;
    transport
        .write_frame(0x8000, MESSAGE_TYPE_SET_TARGET, &target_payload)
        .await
        .map_err(HandlerExit::TransportError)?;

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────
// Job distribution
// ─────────────────────────────────────────────────────────────────────

async fn distribute_job(
    transport: &mut Sv2Transport,
    channels: &mut ConnectionChannels,
    job: &JobBroadcast,
) -> Result<(), HandlerExit> {
    for ch in channels.iter_open_mut() {
        match ch.kind {
            ChannelKind::Standard => {
                // Standard: compute merkle root, send NewMiningJob.
                let merkle_root = crate::jobs::compute_merkle_root(
                    &job.coinbase_tx_prefix,
                    &ch.extranonce_prefix,
                    &job.coinbase_tx_suffix,
                    &job.merkle_path,
                );
                let new_job = sv2_codec::NewMiningJob {
                    channel_id: ch.channel_id,
                    job_id: job.job_id,
                    min_ntime: job.min_ntime,
                    version: job.version,
                    merkle_root,
                };
                let job_payload = new_job.encode().map_err(HandlerExit::CodecError)?;
                transport
                    .write_frame(0x8000, MESSAGE_TYPE_NEW_MINING_JOB, &job_payload)
                    .await
                    .map_err(HandlerExit::TransportError)?;
            }
            ChannelKind::Extended { .. } => {
                // Extended: send raw merkle path and coinbase splits.
                // Miner computes its own merkle root.
                let ext_job = sv2_codec::NewExtendedMiningJob {
                    channel_id: ch.channel_id,
                    job_id: job.job_id,
                    min_ntime: job.min_ntime,
                    version: job.version,
                    version_rolling_allowed: true,
                    merkle_path: job.merkle_path.clone(),
                    coinbase_tx_prefix: job.coinbase_tx_prefix.clone(),
                    coinbase_tx_suffix: job.coinbase_tx_suffix.clone(),
                };
                let job_payload = ext_job.encode().map_err(HandlerExit::CodecError)?;
                transport
                    .write_frame(0x8000, MESSAGE_TYPE_NEW_EXTENDED_MINING_JOB, &job_payload)
                    .await
                    .map_err(HandlerExit::TransportError)?;
            }
        }

        // If there is a prevhash update, send SetNewPrevHash.
        if let Some(ref ph) = job.prevhash_update {
            let set_prev = sv2_codec::SetNewPrevHash {
                channel_id: ch.channel_id,
                job_id: job.job_id,
                prev_hash: ph.prev_hash,
                min_ntime: ph.min_ntime,
                nbits: ph.nbits,
            };
            let ph_payload = set_prev.encode().map_err(HandlerExit::CodecError)?;
            transport
                .write_frame(0x8000, MESSAGE_TYPE_MINING_SET_NEW_PREV_HASH, &ph_payload)
                .await
                .map_err(HandlerExit::TransportError)?;

            ch.record_prevhash_sent(job.job_id, ph.min_ntime);
        }

        ch.record_active_job_sent(job.job_id);
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ── PB-38: a full forward queue must not be reported as acceptance ──
    //
    // The enqueue at the end of the share path used to be a bare
    // `try_send` whose Err arm only logged, with the SubmitShares.Success
    // write immediately below it and no branch in between. The share was
    // dropped, the miner was told it was accepted, and upstream never saw
    // it. That is the pool's accounting path.
    //
    // The codebase had already decided what should happen: GatewayReason
    // maps ShareDroppedQueueFull to the SV2 wire code "stale-share" and
    // deliberately excludes it from the post-ACK telemetry group
    // (ShareEvictedFromQueue, ShareForwardFailed, ShareUpstreamRejected)
    // which `to_sv2_error_code` calls unreachable! on. Enqueue failure
    // happens BEFORE the ACK, so the miner can be told; eviction happens
    // after, so it cannot. That distinction was specified in the enum and
    // never wired to the send site.
    //
    // This drives the REAL handler over a REAL Noise-handshaked transport
    // with a genuinely saturated channel, and reads back the frame the
    // miner would actually receive. PB-38 asked for a test that forces
    // queue saturation because nothing did.

    /// A target that accepts any hash, so the test exercises the enqueue
    /// branch rather than proof-of-work.
    const ANY_POW: [u8; 32] = [0xFF; 32];

    fn pb38_handler_config() -> HandlerConfig {
        HandlerConfig {
            max_channels_per_conn: 4,
            channel_target: ANY_POW,
            channel_open_timeout: Duration::from_secs(5),
            ntime_elapsed_slack_seconds: 3600,
            max_future_block_time_seconds: 7200,
            share_dedup_window_size: 128,
            max_shares_per_second_per_channel: 0,
            gateway_instance_id: "pb38-gw".to_string(),
            share_hmac_secret: Arc::new(std::sync::RwLock::new(Vec::new())),
            extended_channels_enabled: true,
            extranonce_prefix_len: 2,
            vardiff_enabled: false,
            vardiff_target_shares_per_min: 20.0,
            vardiff_retarget_interval: Duration::from_secs(60),
            vardiff_min_difficulty: 1,
            vardiff_max_difficulty: u64::MAX,
            vardiff_max_adjustment_factor: 4.0,
        }
    }

    /// A throwaway submission used only to occupy the relay queue.
    fn pb38_filler_submission() -> ShareSubmission {
        ShareSubmission {
            share_id_hex: "00".repeat(32),
            version: 0x2000_0000,
            prev_hash_wire_hex: "00".repeat(32),
            prev_hash_display_hex: "00".repeat(32),
            merkle_root_wire_hex: "00".repeat(32),
            merkle_root_display_hex: "00".repeat(32),
            ntime: 0,
            nbits: 0x1d00_ffff,
            nonce: 0,
            event_id_hex: "00".repeat(32),
            worker_id: "filler".to_string(),
            validation_level: "full".to_string(),
            gateway_instance_id: "pb38-gw".to_string(),
            channel_id: 1,
            sequence_number: 0,
            job_id: 42,
            template_id: 1,
            block_height: 1,
            pool_account_id: None,
            timestamp_ms: 0,
            difficulty_u64: 1,
            difficulty_display: 1.0,
            source_instance_id: "pb38".to_string(),
            gateway_signature_hex: String::new(),
        }
    }

    fn pb38_job(ntime: u32) -> crate::jobs::JobRecord {
        crate::jobs::JobRecord {
            job_id: 42,
            template_id: 1,
            block_height: 1,
            version: 0x2000_0000,
            prev_hash: [0u8; 32],
            nbits: 0x1d00_ffff,
            coinbase_tx_prefix: vec![0x01, 0x00, 0x00, 0x00],
            coinbase_tx_suffix: vec![0xFF, 0xFF, 0xFF, 0xFF],
            merkle_path: Vec::new(),
            activation_min_ntime: ntime.saturating_sub(600),
            raw_min_ntime: ntime.saturating_sub(600),
            raw_curtime: ntime,
            source_instance_id: "pb38".to_string(),
            activated: true,
            created_at: std::time::Instant::now(),
        }
    }

    /// Drive the REAL share handler over a REAL Noise-handshaked transport
    /// with a genuinely saturated relay queue, and return the SV2 `msg_type`
    /// the miner actually receives. `extended` selects which of the two
    /// handlers is exercised; PB-38 notes the defect repeats in both.
    async fn pb38_reply_msg_type_on_full_queue(
        extended: bool,
    ) -> (u8, String, Vec<(String, Option<String>)>) {
        use crate::transport::perform_handshake;
        use secp256k1::Keypair;
        use tokio::net::TcpListener;

        let secp = secp256k1::Secp256k1::new();
        let authority_kp = Keypair::new(&secp, &mut rand::thread_rng());
        let authority_pubkey = authority_kp.x_only_public_key().0;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Saturate the relay queue: capacity one, already occupied. The
        // receiver is held so the queue cannot drain.
        let (share_forward_tx, _share_forward_rx) = mpsc::channel::<ShareSubmission>(1);
        share_forward_tx
            .try_send(pb38_filler_submission())
            .expect("first send fills the queue");
        assert!(
            share_forward_tx.try_send(pb38_filler_submission()).is_err(),
            "queue must be saturated or this test proves nothing"
        );
        let (share_event_tx, mut share_event_rx) = mpsc::channel::<ShareAcceptedEvent>(64);

        #[allow(clippy::cast_possible_truncation)]
        let ntime = (unix_ms_now() / 1000) as u32;

        let responder = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            let mut transport =
                perform_handshake(stream, &authority_kp, 3600, Duration::from_secs(5))
                    .await
                    .unwrap();

            let config = pb38_handler_config();
            let mut channels = ConnectionChannels::new(config.max_channels_per_conn);
            if extended {
                channels
                    .open_extended_channel(
                        1,
                        vec![0xAA, 0xBB],
                        "w1".to_string(),
                        None,
                        ANY_POW,
                        0,
                        4,
                        6,
                    )
                    .unwrap();
            } else {
                channels
                    .open_channel(1, vec![0xAA, 0xBB], "w1".to_string(), None, ANY_POW, 0)
                    .unwrap();
            }

            let mut table = JobTable::new(300_000, 64);
            table.insert(pb38_job(ntime));
            let job_table = Arc::new(tokio::sync::RwLock::new(table));
            let mut dedup = ShareDedupSet::new(128);
            let peer_state = PeerState::new(peer);
            let up = Counter::default();
            let down = Counter::default();

            let (_hdr, payload) = transport.read_frame().await.unwrap();

            if extended {
                handle_submit_shares_extended(
                    &mut transport,
                    &peer_state,
                    &mut channels,
                    &config,
                    &job_table,
                    &mut dedup,
                    &share_event_tx,
                    &share_forward_tx,
                    &payload,
                    &up,
                    &down,
                )
                .await
            } else {
                handle_submit_shares(
                    &mut transport,
                    &peer_state,
                    &mut channels,
                    &config,
                    &job_table,
                    &mut dedup,
                    &share_event_tx,
                    &share_forward_tx,
                    &payload,
                    &up,
                    &down,
                )
                .await
            }
        });

        let (msg_type, error_code) = pb38_miner_side(addr, authority_pubkey, extended, ntime).await;
        responder.await.unwrap().unwrap();

        // Drain the accounting stream. The gateway's own books must agree
        // with what the miner was told: a T2 review found the success event
        // was emitted BEFORE the enqueue, so a rejected share was still
        // credited in shares_total, in the channel registry and as a WAL
        // pending record no forward result would ever complete.
        let mut events = Vec::new();
        while let Ok(evt) = share_event_rx.try_recv() {
            events.push((evt.sv2_response.to_string(), evt.reason_code.clone()));
        }
        (msg_type, error_code, events)
    }

    /// The miner half of the PB-38 harness: complete the Noise handshake,
    /// submit one share, and return the `msg_type` of the reply frame.
    async fn pb38_miner_side(
        addr: std::net::SocketAddr,
        authority_pubkey: secp256k1::XOnlyPublicKey,
        extended: bool,
        ntime: u32,
    ) -> (u8, String) {
        use noise_sv2::{INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE, Initiator};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpStream;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut initiator = Initiator::from_raw_k(authority_pubkey.serialize()).unwrap();
        let first = initiator.step_0().unwrap();
        stream.write_all(&first).await.unwrap();
        stream.flush().await.unwrap();
        let mut response = [0u8; INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE];
        stream.read_exact(&mut response).await.unwrap();
        let mut codec = initiator.step_2(response).unwrap();

        let (msg_type, body) = if extended {
            let share = sv2_codec::SubmitSharesExtended {
                channel_id: 1,
                sequence_number: 7,
                job_id: 42,
                nonce: 0,
                ntime,
                version: 0x2000_0000,
                extranonce: vec![0x01, 0x02, 0x03, 0x04],
            };
            (MESSAGE_TYPE_SUBMIT_SHARES_EXTENDED, share.encode().unwrap())
        } else {
            let share = sv2_codec::SubmitSharesStandard {
                channel_id: 1,
                sequence_number: 7,
                job_id: 42,
                nonce: 0,
                ntime,
                version: 0x2000_0000,
            };
            (MESSAGE_TYPE_SUBMIT_SHARES_STANDARD, share.encode().unwrap())
        };

        #[allow(clippy::cast_possible_truncation)]
        let hdr = crate::transport::Sv2FrameHeader {
            extension_type: 0x0000,
            msg_type,
            msg_length: body.len() as u32,
        };
        let mut frame = Vec::new();
        frame.extend_from_slice(&hdr.to_bytes());
        frame.extend_from_slice(&body);
        codec.encrypt(&mut frame).unwrap();
        #[allow(clippy::cast_possible_truncation)]
        let len_bytes = (frame.len() as u16).to_be_bytes();
        stream.write_all(&len_bytes).await.unwrap();
        stream.write_all(&frame).await.unwrap();
        stream.flush().await.unwrap();

        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await.unwrap();
        let resp_len = u16::from_be_bytes(len_buf) as usize;
        let mut encrypted = vec![0u8; resp_len];
        stream.read_exact(&mut encrypted).await.unwrap();
        codec.decrypt(&mut encrypted).unwrap();
        let mut hdr_bytes = [0u8; crate::transport::SV2_FRAME_HEADER_SIZE];
        hdr_bytes.copy_from_slice(&encrypted[..crate::transport::SV2_FRAME_HEADER_SIZE]);

        let hdr = crate::transport::Sv2FrameHeader::parse(&hdr_bytes);
        let body = &encrypted[crate::transport::SV2_FRAME_HEADER_SIZE..];
        let error_code = if hdr.msg_type == MESSAGE_TYPE_SUBMIT_SHARES_ERROR {
            sv2_codec::SubmitSharesError::decode(body)
                .map(|e| e.error_code)
                .unwrap_or_default()
        } else {
            String::new()
        };
        (hdr.msg_type, error_code)
    }

    /// Assert the WHOLE contract for a queue-full drop, not just that some
    /// error came back. A T2 reviewer noted the first version of these tests
    /// would have passed the moment anything rejected the fixture earlier in
    /// the pipeline, for an entirely unrelated reason.
    fn pb38_assert_rejected(
        msg_type: u8,
        error_code: &str,
        events: &[(String, Option<String>)],
        what: &str,
    ) {
        assert_ne!(
            msg_type, MESSAGE_TYPE_SUBMIT_SHARES_SUCCESS,
            "{what}: the forward queue was full and the share was dropped, but \
             the miner was told SubmitShares.Success. This is the pool's \
             accounting path: the miner is credited for a share upstream never \
             received."
        );
        assert_eq!(
            msg_type, MESSAGE_TYPE_SUBMIT_SHARES_ERROR,
            "{what}: a share dropped at enqueue must be reported as an error"
        );
        assert_eq!(
            error_code,
            GatewayReason::ShareDroppedQueueFull.to_sv2_error_code(),
            "{what}: the error must be the one ShareDroppedQueueFull maps to, \
             otherwise this test passes on any unrelated earlier rejection and \
             proves nothing about the enqueue branch"
        );
        assert!(
            !events.iter().any(|(response, _)| response == "success"),
            "{what}: the gateway told the miner the share was REJECTED but \
             filed a success accounting event, which credits shares_total, the \
             channel registry and a WAL pending record for a share that was \
             thrown away. Events seen: {events:?}"
        );
        assert!(
            events.iter().any(|(response, reason)| response == "error"
                && reason.as_deref() == Some(GatewayReason::ShareDroppedQueueFull.as_str())),
            "{what}: the accounting stream must carry the rejection with \
             reason_code share_dropped_queue_full. Events seen: {events:?}"
        );
    }

    #[tokio::test]
    async fn full_forward_queue_rejects_a_standard_share_to_the_miner() {
        let (msg_type, error_code, events) = pb38_reply_msg_type_on_full_queue(false).await;
        pb38_assert_rejected(msg_type, &error_code, &events, "standard share");
    }

    #[tokio::test]
    async fn full_forward_queue_rejects_an_extended_share_to_the_miner() {
        let (msg_type, error_code, events) = pb38_reply_msg_type_on_full_queue(true).await;
        pb38_assert_rejected(msg_type, &error_code, &events, "extended share");
    }

    #[test]
    fn handler_exit_display() {
        let exit = HandlerExit::SetupRejected("bad protocol".to_string());
        let s = format!("{exit}");
        assert!(s.contains("setup rejected"), "got: {s}");
    }

    #[test]
    fn job_broadcast_clone() {
        let job = JobBroadcast {
            job_id: 1,
            version: 0x2000_0000,
            coinbase_tx_prefix: vec![0x01, 0x00, 0x00, 0x00],
            coinbase_tx_suffix: vec![0xFF, 0xFF, 0xFF, 0xFF],
            merkle_path: vec![],
            prevhash_update: Some(PrevhashUpdate {
                prev_hash: [0xBB; 32],
                min_ntime: 1_700_000_000,
                nbits: 0x1703_4219,
            }),
            min_ntime: None,
        };
        let cloned = job.clone();
        assert_eq!(cloned.job_id, 1);
        assert!(cloned.prevhash_update.is_some());
    }

    #[test]
    fn handler_config_fields() {
        let config = HandlerConfig {
            max_channels_per_conn: 256,
            channel_target: [0xFF; 32],
            channel_open_timeout: Duration::from_secs(30),
            ntime_elapsed_slack_seconds: 2,
            max_future_block_time_seconds: 7200,
            share_dedup_window_size: 10_000,
            max_shares_per_second_per_channel: 0,
            gateway_instance_id: "test-gw".to_string(),
            share_hmac_secret: Arc::new(std::sync::RwLock::new(Vec::new())),
            extended_channels_enabled: true,
            extranonce_prefix_len: 4,
            vardiff_enabled: false,
            vardiff_target_shares_per_min: 20.0,
            vardiff_retarget_interval: Duration::from_secs(90),
            vardiff_min_difficulty: 1,
            vardiff_max_difficulty: u64::MAX,
            vardiff_max_adjustment_factor: 4.0,
        };
        assert_eq!(config.max_channels_per_conn, 256);
        assert_eq!(config.ntime_elapsed_slack_seconds, 2);
        assert_eq!(config.gateway_instance_id, "test-gw");
        assert!(config.extended_channels_enabled);
        assert!(!config.vardiff_enabled);
    }
}
