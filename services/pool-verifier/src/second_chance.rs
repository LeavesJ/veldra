//! PB-40: second-chance lookup at Class M rejection time.
//!
//! The Class M check compares a template's txids against a
//! `getrawmempool` snapshot up to `poll_interval_secs` old, while
//! `getblocktemplate` preferentially selects freshly-arrived high-fee
//! transactions. Those arrivals score "unknown to verifier view" and
//! past `tolerance_pct` the template is rejected. On the Setup B node
//! that produced 68 rejections in 7.5 hours, and a live query caught
//! one mid-flight: 10 of 10 sampled txids were IN bitcoind's mempool
//! seconds after the rejection fired.
//!
//! This module asks bitcoind directly, at the moment of rejection,
//! whether it knows each transaction the stale view did not. It closes
//! two defects with one mechanism:
//!
//! 1. **The false positive.** A transaction bitcoind holds is not
//!    unknown, so the unknown count is recomputed against the answer
//!    and the rejection is withdrawn when the recomputed ratio is
//!    within tolerance.
//! 2. **The unadjudicable evidence.** The answer is recorded on the
//!    verdict. It cannot be recovered afterwards: the same txids
//!    sampled from a 35-minute-old rejection came back 9 of 9 ABSENT,
//!    because they are the churny tail that gets RBF-replaced or
//!    evicted from a 93k mempool within minutes. A T+7 review of
//!    week-old records would find them absent and score every
//!    rejection a TRUE positive, which is the wrong answer with a
//!    checkmark on it.

use std::collections::HashSet;
use std::time::Duration;

use thiserror::Error;
use tracing::warn;

use crate::bitcoind_rpc::{BitcoindClient, RpcError};

/// Wall-clock budget for the whole second-chance lookup, mempool
/// fetch and block walk together.
///
/// Derived from the caller's own deadline, not picked for feel. The
/// template-manager abandons a verdict after 4 seconds
/// (`services/template-manager/src/main.rs:1679`
/// `verdict_timeout = Duration::from_secs(4)`), and the bitcoind
/// client's per-request timeout is 5 seconds
/// (`main.rs::build_phase2_mempool_view`), so an unbounded lookup
/// could outlive the verdict it is trying to correct and convert a
/// fast false rejection into a timeout, which is strictly worse: the
/// operator loses the verdict entirely instead of getting a wrong one
/// they can see. Two seconds leaves the rest of the template handling
/// half the window. On the Setup B node `getrawmempool` against a 94k
/// mempool over loopback returns in well under that.
pub const SECOND_CHANCE_DEADLINE: Duration = Duration::from_secs(2);

/// Most blocks walked back from the tip when looking for template
/// transactions that were mined between template construction and this
/// check.
///
/// The walk's real bound is `template.block_height`: a template
/// building block N was assembled from a mempool that by construction
/// excluded everything already mined at heights below N, so only
/// blocks at height >= N can hold one of its transactions. This cap is
/// the backstop for a template so old that the honest walk would be
/// long, and reaching it is recorded on the verdict rather than
/// silently truncating the search.
pub const MAX_RECENT_BLOCKS_SCANNED: u32 = 6;

/// Cap on still-absent txids recorded in the durable evidence.
///
/// The evidence exists to make a rejection adjudicable by hand at T+7.
/// A reviewer needs enough identities to spot-check, not all of them,
/// and the verdict line has a wire budget shared with the rest of the
/// record.
pub const ABSENT_SAMPLE_CAP: usize = 32;

/// How much of the block walk actually happened.
///
/// Exists because the three shapes used to be indistinguishable in the
/// durable record: an errored walk and a healthy walk with nothing to
/// scan both produced `blocks_scanned: 0, block_walk_truncated: false`,
/// so a verdict could be labelled `upheld` (which the runbook defines
/// as a genuine detection candidate) on a mined-case check that never
/// ran. Coverage is now a value the adjudication has to look at, not a
/// pair of numbers a reader has to infer from.
#[derive(Debug, Clone)]
pub enum WalkCoverage {
    /// Every block at or above the template's height was walked, so
    /// `mined` is exact and absence from it is real evidence.
    Complete {
        txids: HashSet<[u8; 32]>,
        blocks_scanned: u32,
        tip_height: Option<u32>,
    },
    /// The walk stopped at [`MAX_RECENT_BLOCKS_SCANNED`] with blocks
    /// still owed, so `mined` is a floor rather than a count.
    Truncated {
        txids: HashSet<[u8; 32]>,
        blocks_scanned: u32,
        tip_height: Option<u32>,
    },
    /// An RPC failed part way. Whatever was collected is real, but
    /// absence from it proves nothing.
    Failed {
        txids: HashSet<[u8; 32]>,
        blocks_scanned: u32,
        tip_height: Option<u32>,
        error: String,
    },
}

impl WalkCoverage {
    /// Whether absence from the collected set is trustworthy evidence.
    /// Only a complete walk can support "this transaction was not
    /// mined", which is half of what an `upheld` verdict asserts.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        matches!(self, WalkCoverage::Complete { .. })
    }

    /// Operator-facing reason the walk fell short, `None` when it did not.
    #[must_use]
    pub fn shortfall(&self) -> Option<String> {
        match self {
            WalkCoverage::Complete { .. } => None,
            WalkCoverage::Truncated { blocks_scanned, .. } => Some(format!(
                "block walk hit the {MAX_RECENT_BLOCKS_SCANNED}-block cap after {blocks_scanned} \
                 blocks with more still owed; the mined count is a floor"
            )),
            WalkCoverage::Failed { error, .. } => Some(format!("block walk failed after {error}")),
        }
    }

    #[cfg(test)]
    fn blocks_scanned_for_test(&self) -> u32 {
        match self {
            WalkCoverage::Complete { blocks_scanned, .. }
            | WalkCoverage::Truncated { blocks_scanned, .. }
            | WalkCoverage::Failed { blocks_scanned, .. } => *blocks_scanned,
        }
    }

    /// Decompose into the fields `BitcoindAnswer` carries. The bool is
    /// the legacy `block_walk_truncated` flag, kept because the durable
    /// record and the soak scripts already read it; `shortfall()` is
    /// the value that actually distinguishes a failed walk from a
    /// complete one, since Complete and Failed both report `false`
    /// here.
    fn parts(self) -> (HashSet<[u8; 32]>, u32, Option<u32>, bool) {
        let truncated = matches!(self, WalkCoverage::Truncated { .. });
        match self {
            WalkCoverage::Complete {
                txids,
                blocks_scanned,
                tip_height,
            }
            | WalkCoverage::Truncated {
                txids,
                blocks_scanned,
                tip_height,
            }
            | WalkCoverage::Failed {
                txids,
                blocks_scanned,
                tip_height,
                ..
            } => (txids, blocks_scanned, tip_height, truncated),
        }
    }
}

/// What bitcoind said about the transactions the served view did not
/// contain, gathered at rejection time.
///
/// Deliberately a plain data record separated from the RPC calls that
/// fill it, so the adjudication arithmetic is testable without a node.
#[derive(Debug, Clone, Default)]
pub struct BitcoindAnswer {
    /// Unknown transactions bitcoind CONFIRMED it holds right now.
    ///
    /// Named for what it is. It was `fresh_mempool` when it held a
    /// whole-mempool snapshot; it is now the probed subset that came
    /// back present, and calling it "the mempool" would invite a reader
    /// to treat absence from it as absence from the mempool. Absence
    /// from this set means only "not confirmed present".
    pub present_in_mempool: HashSet<[u8; 32]>,
    /// Unknown transactions whose probe returned no usable answer.
    /// Proves nothing in either direction; kept separate from the
    /// proven-absent count so the two can never be conflated.
    pub unadjudicated: HashSet<[u8; 32]>,
    /// Txids of every block mined at or above the template's own
    /// height, i.e. mined since the template was built.
    pub recent_block_txids: HashSet<[u8; 32]>,
    /// Blocks actually walked. Zero is the normal answer: it means the
    /// tip had not advanced past the template's parent.
    pub blocks_scanned: u32,
    /// `true` when the walk stopped at [`MAX_RECENT_BLOCKS_SCANNED`]
    /// rather than at the template's height, so a reader can tell a
    /// complete search from a truncated one.
    pub block_walk_truncated: bool,
    /// Chain tip height at lookup time, `None` when the walk could not
    /// reach bitcoind at all. Recorded so a reader can compute the gap
    /// the walk was supposed to cover and check `blocks_scanned`
    /// against it, which was impossible while the record carried no
    /// tip.
    pub tip_height: Option<u32>,
    /// Why the block walk fell short, `None` when it did not. When this
    /// is `Some`, absence from `recent_block_txids` is NOT evidence the
    /// transaction was unmined, and the adjudication must not be
    /// reported as a completed one.
    pub block_walk_shortfall: Option<String>,
}

/// Where one formerly-unknown transaction actually lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxAdjudication {
    /// bitcoind holds it in the mempool right now. The served view was
    /// simply older than the transaction.
    InMempool,
    /// Absent from the mempool because it was mined into a block at or
    /// above the template's height, i.e. after the template was built.
    Mined,
    /// bitcoind was asked and did not give a usable answer. Distinct
    /// from `Absent`, which is a positive statement that it does not
    /// hold the transaction.
    Unadjudicated,
    /// bitcoind knows it in neither place.
    Absent,
}

/// The recomputed Class M position after bitcoind answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adjudication {
    /// Non-coinbase transactions in the template.
    pub total: u32,
    /// Transactions the served view did not contain.
    pub unknown_before: u32,
    /// Of those, held in bitcoind's mempool at rejection time.
    pub in_mempool: u32,
    /// Of those, mined since the template was built.
    pub mined: u32,
    /// Of those, bitcoind answered that it holds them in neither place.
    /// PROVEN absent. Narrowed from "not found" by the targeted-probe
    /// change: the unproven cases now live in `unadjudicated`, because
    /// the old breadth is what let an unestablished count read as
    /// evidence for a detection.
    pub still_absent: u32,
    /// Of those, nobody established anything about. Disjoint from
    /// `still_absent`.
    pub unadjudicated: u32,
    /// Identities of the still-absent, bounded by
    /// [`ABSENT_SAMPLE_CAP`]. Internal byte order.
    pub still_absent_sample: Vec<[u8; 32]>,
    pub blocks_scanned: u32,
    pub block_walk_truncated: bool,
    /// Chain tip at lookup time, so a reader can check `blocks_scanned`
    /// against the gap the walk owed.
    pub tip_height: Option<u32>,
    /// Why the block walk fell short, `None` when it did not. `Some`
    /// means `mined` is a floor and `still_absent` may include
    /// transactions that were in fact mined, so absence is not evidence.
    pub block_walk_shortfall: Option<String>,
}

/// Why a second-chance lookup produced no answer.
///
/// Two variants because they call for different operator action: an
/// [`SecondChanceError::Rpc`] means bitcoind is broken or
/// misconfigured, a [`SecondChanceError::Deadline`] means it is slow
/// enough to threaten the upstream verdict budget. Both uphold the
/// rejection; only one of them is fixed by tuning.
#[derive(Debug, Error)]
pub enum SecondChanceError {
    #[error("second-chance lookup failed: {0}")]
    Rpc(#[from] RpcError),

    #[error("second-chance lookup exceeded its {SECOND_CHANCE_DEADLINE:?} deadline")]
    Deadline,

    #[error(
        "getrawmempool succeeded but returned an empty set, which cannot establish that any \
         transaction is absent"
    )]
    EmptyMempool,

    /// The mempool half succeeded and the block walk did not, and the
    /// mempool half alone did not explain enough transactions to
    /// withdraw the rejection. Absence from an incomplete walk is not
    /// evidence a transaction was unmined, so the verdict is reported
    /// unadjudicated rather than as a confirmed detection.
    #[error("block walk incomplete, so the mined case could not be ruled out: {0}")]
    BlockWalkIncomplete(String),
}

impl SecondChanceError {
    /// Stable label for the `verifier_phase2_second_chance_total`
    /// metric and the durable verdict record.
    #[must_use]
    pub fn as_label(&self) -> &'static str {
        match self {
            SecondChanceError::Rpc(_) => "rpc_error",
            SecondChanceError::Deadline => "deadline",
            SecondChanceError::EmptyMempool => "empty_mempool",
            SecondChanceError::BlockWalkIncomplete(_) => "block_walk_incomplete",
        }
    }
}

/// What the second-chance lookup did to a Class M rejection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecondChanceOutcome {
    /// bitcoind knew enough of the unknown transactions to bring the
    /// recomputed unknown ratio back within tolerance. The rejection
    /// is withdrawn and the template accepted.
    Withdrawn(Adjudication),
    /// bitcoind answered and the rejection still stands on the
    /// recomputed count.
    Upheld(Adjudication),
    /// bitcoind could not be asked. The rejection stands
    /// **unadjudicated**: this is not the same as `Upheld`, and a
    /// reviewer must not read it as one.
    ///
    /// Carries the first-pass counts so the durable record is complete
    /// whichever way the lookup went. Leaving them for the caller to
    /// fill in afterwards would be a contract nothing enforces, and a
    /// record showing `unknown_before: 0` beside a rejection is worse
    /// than no record.
    LookupFailed {
        total: u32,
        unknown_before: u32,
        reason: String,
        kind: String,
    },
}

impl SecondChanceOutcome {
    /// Stable label for `verifier_phase2_second_chance_total`.
    #[must_use]
    pub fn as_label(&self) -> &'static str {
        match self {
            SecondChanceOutcome::Withdrawn(_) => "withdrawn",
            SecondChanceOutcome::Upheld(_) => "upheld",
            SecondChanceOutcome::LookupFailed { .. } => "lookup_failed",
        }
    }
}

/// Whether an unknown count crosses the configured tolerance.
///
/// This exists because the first Class M pass
/// ([`crate::mempool_view::evaluate`]) and the second-chance recompute
/// ([`Adjudication::still_exceeds`]) are the two halves of one
/// decision: a template that rejects under one rule and recovers under
/// a differently-rounded copy of it would be a defect no test asserting
/// either half alone could see. Both call this.
#[must_use]
pub fn exceeds_tolerance(unknown_count: u32, total: u32, tolerance_pct: f64) -> bool {
    if total == 0 {
        return false;
    }
    let ratio_pct = (f64::from(unknown_count) / f64::from(total)) * 100.0;
    ratio_pct > tolerance_pct
}

impl Adjudication {
    /// Unknown transactions not proven known to bitcoind: proven absent
    /// plus unestablished. This is what the tolerance decision uses.
    ///
    /// Counting the unestablished ones here is the pessimistic reading
    /// and it is the safe one: it can only hold a rejection, never
    /// manufacture a recovery.
    #[must_use]
    pub fn not_proven_known(&self) -> u32 {
        self.still_absent.saturating_add(self.unadjudicated)
    }

    /// Whether the rejection still stands once the transactions
    /// bitcoind proved it knows have been removed from the count.
    #[must_use]
    pub fn still_exceeds(&self, tolerance_pct: f64) -> bool {
        exceeds_tolerance(self.not_proven_known(), self.total, tolerance_pct)
    }
}

/// Score each unknown transaction against what bitcoind said.
///
/// Pure: takes the gathered answer rather than making the calls, so
/// every branch is reachable in a unit test without a node.
#[must_use]
pub fn adjudicate(total: u32, unknown: &[[u8; 32]], answer: &BitcoindAnswer) -> Adjudication {
    let mut in_mempool = 0u32;
    let mut mined = 0u32;
    let mut unadjudicated = 0u32;
    let mut still_absent = 0u32;
    let mut still_absent_sample = Vec::new();

    for txid in unknown {
        match classify(txid, answer) {
            TxAdjudication::InMempool => in_mempool = in_mempool.saturating_add(1),
            TxAdjudication::Mined => mined = mined.saturating_add(1),
            TxAdjudication::Unadjudicated => unadjudicated = unadjudicated.saturating_add(1),
            TxAdjudication::Absent => {
                still_absent = still_absent.saturating_add(1);
                if still_absent_sample.len() < ABSENT_SAMPLE_CAP {
                    still_absent_sample.push(*txid);
                }
            }
        }
    }

    Adjudication {
        total,
        unknown_before: u32::try_from(unknown.len()).unwrap_or(u32::MAX),
        in_mempool,
        mined,
        still_absent,
        unadjudicated,
        still_absent_sample,
        blocks_scanned: answer.blocks_scanned,
        block_walk_truncated: answer.block_walk_truncated,
        tip_height: answer.tip_height,
        block_walk_shortfall: answer.block_walk_shortfall.clone(),
    }
}

/// Mempool membership is checked first: a transaction in the mempool
/// right now is the common case this whole mechanism exists for, and a
/// transaction cannot be in the mempool and mined at the same time.
fn classify(txid: &[u8; 32], answer: &BitcoindAnswer) -> TxAdjudication {
    if answer.present_in_mempool.contains(txid) {
        TxAdjudication::InMempool
    } else if answer.recent_block_txids.contains(txid) {
        TxAdjudication::Mined
    } else if answer.unadjudicated.contains(txid) {
        TxAdjudication::Unadjudicated
    } else {
        TxAdjudication::Absent
    }
}

/// The second-chance answer as it is written to the durable verdict
/// log, and the whole reason this mechanism records anything.
///
/// PB-40's dangerous half: the answer is unrecoverable after the
/// fact. Sampled txids from a 35-minute-old rejection came back 9 of 9
/// ABSENT from bitcoind, not because they were ever invalid but
/// because they are the churny tail that gets RBF-replaced or evicted
/// from a 93k mempool within minutes. A T+7 reviewer re-querying
/// week-old records would find them absent and score every rejection a
/// TRUE positive. This record is what that reviewer must read instead.
///
/// Distinct from [`Adjudication`] on purpose: txids are emitted in
/// DISPLAY order (byte-reversed from the internal order the shield
/// works in), because the reviewer's next step is pasting them into
/// `bitcoin-cli` or a block explorer, both of which speak display
/// order.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MempoolAdjudicationRecord {
    /// `withdrawn`, `upheld`, or `lookup_failed`.
    pub outcome: String,
    /// Non-coinbase transactions in the template.
    pub total: u32,
    /// Unknown to the polled view, before bitcoind was asked.
    pub unknown_before: u32,
    /// Held in bitcoind's mempool at rejection time. A non-zero value
    /// here is the PB-40 defect being caught in the act.
    pub in_mempool: u32,
    /// Mined into a block at or above the template's height.
    pub mined: u32,
    /// Unknown to bitcoind in both places. This is the only count that
    /// can support a true-positive claim.
    pub still_absent: u32,
    /// Unknowns nobody established anything about. Disjoint from
    /// `still_absent`. Non-zero means this record cannot support a
    /// detection claim regardless of what `still_absent` says.
    #[serde(default)]
    pub unadjudicated: u32,
    pub blocks_scanned: u32,
    /// `true` when the block walk hit [`MAX_RECENT_BLOCKS_SCANNED`],
    /// so `mined` may undercount.
    pub block_walk_truncated: bool,
    /// Chain tip height at lookup time. Present so a reader can compute
    /// the gap the walk owed (`tip_height - template height + 1`) and
    /// check it against `blocks_scanned`, which was impossible while the
    /// record carried no tip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tip_height: Option<u32>,
    /// Why the block walk fell short. When present, `mined` is a FLOOR
    /// and `still_absent` may include mined transactions, so this record
    /// cannot support a detection claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_walk_shortfall: Option<String>,
    /// Still-absent txids in DISPLAY order, capped at
    /// [`ABSENT_SAMPLE_CAP`].
    pub still_absent_sample: Vec<String>,
    /// Present only for `lookup_failed`: why bitcoind was not asked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lookup_error: Option<String>,
    /// Present only for `lookup_failed`: `rpc_error` or `deadline`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lookup_error_kind: Option<String>,
}

impl From<&SecondChanceOutcome> for MempoolAdjudicationRecord {
    fn from(outcome: &SecondChanceOutcome) -> Self {
        let label = outcome.as_label().to_string();
        match outcome {
            SecondChanceOutcome::Withdrawn(adj) | SecondChanceOutcome::Upheld(adj) => Self {
                outcome: label,
                total: adj.total,
                unknown_before: adj.unknown_before,
                in_mempool: adj.in_mempool,
                mined: adj.mined,
                still_absent: adj.still_absent,
                unadjudicated: adj.unadjudicated,
                blocks_scanned: adj.blocks_scanned,
                block_walk_truncated: adj.block_walk_truncated,
                tip_height: adj.tip_height,
                block_walk_shortfall: adj.block_walk_shortfall.clone(),
                still_absent_sample: adj
                    .still_absent_sample
                    .iter()
                    .map(|t| {
                        let mut display = *t;
                        display.reverse();
                        hex::encode(display)
                    })
                    .collect(),
                lookup_error: None,
                lookup_error_kind: None,
            },
            SecondChanceOutcome::LookupFailed {
                total,
                unknown_before,
                reason,
                kind,
            } => Self {
                outcome: label,
                // The first-pass counts are real and are recorded. The
                // three adjudication counts below stay zero because
                // nothing was adjudicated, which `outcome` states
                // outright so they cannot be read as "bitcoind knew
                // none of them".
                total: *total,
                unknown_before: *unknown_before,
                in_mempool: 0,
                mined: 0,
                still_absent: 0,
                unadjudicated: 0,
                blocks_scanned: 0,
                block_walk_truncated: false,
                tip_height: None,
                block_walk_shortfall: None,
                still_absent_sample: Vec::new(),
                lookup_error: Some(reason.clone()),
                lookup_error_kind: Some(kind.clone()),
            },
        }
    }
}

/// Asks bitcoind, at rejection time, about transactions the polled
/// view did not contain.
///
/// Holds its own [`BitcoindClient`] rather than borrowing the polling
/// task's: the task moves its client into a `tokio::spawn` that runs
/// for the process lifetime, and the client is a cheap `reqwest`
/// handle clone over a shared connection pool.
#[derive(Debug, Clone)]
pub struct SecondChance {
    client: BitcoindClient,
}

impl SecondChance {
    #[must_use]
    pub fn new(client: BitcoindClient) -> Self {
        Self { client }
    }

    /// Gather bitcoind's answer for a template building block
    /// `template_height`, within [`SECOND_CHANCE_DEADLINE`].
    ///
    /// The deadline is enforced here rather than at the call site so
    /// no future caller can forget it and put the upstream verdict
    /// budget at risk.
    ///
    /// # Errors
    ///
    /// [`SecondChanceError::Rpc`] when bitcoind answered badly,
    /// [`SecondChanceError::Deadline`] when it did not answer in time.
    /// Either way the caller must let the original rejection stand: a
    /// lookup that could not run is not evidence of absence, and this
    /// module exists because that exact distinction was lost once
    /// already, when silently failing `bitcoin-cli` calls read as
    /// "transaction genuinely absent" for two rounds of investigation.
    pub async fn ask(&self, template_height: u32) -> Result<BitcoindAnswer, SecondChanceError> {
        tokio::time::timeout(SECOND_CHANCE_DEADLINE, self.gather(template_height))
            .await
            .map_err(|_| SecondChanceError::Deadline)?
    }

    async fn gather(&self, template_height: u32) -> Result<BitcoindAnswer, SecondChanceError> {
        let present_in_mempool: HashSet<[u8; 32]> =
            self.client.get_raw_mempool().await?.into_iter().collect();

        // The same floor the view install path applies
        // (`mempool_view::MIN_INSTALLABLE_MEMPOOL_SIZE`), for the same
        // reason and on the same evidence grounds. A successful but
        // empty `getrawmempool` carries exactly the information content
        // of an RPC error: it cannot tell us that any transaction is
        // absent. Scoring every unknown "absent" against it would
        // uphold the rejection and record it as an adjudicated
        // detection candidate. Refusing it here means the caller emits
        // `lookup_failed` instead, which upholds the rejection just the
        // same but says truthfully that nobody adjudicated it.
        if present_in_mempool.len() < crate::mempool_view::MIN_INSTALLABLE_MEMPOOL_SIZE {
            warn!(
                size = present_in_mempool.len(),
                min = crate::mempool_view::MIN_INSTALLABLE_MEMPOOL_SIZE,
                "second chance: getrawmempool succeeded but returned an empty set; refusing to \
                 adjudicate against it. Every unknown transaction would score absent and the \
                 rejection would be recorded as a confirmed detection"
            );
            return Err(SecondChanceError::EmptyMempool);
        }

        let coverage = self.recent_blocks(template_height).await;
        let block_walk_shortfall = coverage.shortfall();
        let (recent_block_txids, blocks_scanned, tip_height, block_walk_truncated) =
            coverage.parts();

        Ok(BitcoindAnswer {
            present_in_mempool,
            // Task 4 replaces the whole-mempool fetch with targeted
            // probes, which is what can actually produce this.
            unadjudicated: HashSet::new(),
            recent_block_txids,
            blocks_scanned,
            block_walk_truncated,
            tip_height,
            block_walk_shortfall,
        })
    }

    /// Walk back from the tip collecting txids of every block at or
    /// above `template_height`.
    ///
    /// A template building block N was assembled from a mempool that
    /// excluded everything mined below N, so a block below N cannot
    /// hold one of its transactions and the walk stops there. Normally
    /// the tip is at N-1 and this scans nothing.
    ///
    /// A block-walk failure is degraded rather than fatal: the mempool
    /// half of the answer is the load-bearing one and is already in
    /// hand. The shortfall surfaces as `blocks_scanned` lower than the
    /// height gap on the recorded verdict.
    async fn recent_blocks(&self, template_height: u32) -> WalkCoverage {
        let mut collected = HashSet::new();
        let mut scanned = 0u32;

        let mut hash = match self.client.get_best_block_hash().await {
            Ok(h) => h,
            Err(e) => {
                warn!(error = %e, "second chance: getbestblockhash failed; the mined case cannot be ruled out for this verdict");
                return WalkCoverage::Failed {
                    txids: collected,
                    blocks_scanned: 0,
                    tip_height: None,
                    error: e.to_string(),
                };
            }
        };

        let mut tip_height = None;
        loop {
            let block = match self.client.get_block_txids(&hash).await {
                Ok(b) => b,
                Err(e) => {
                    warn!(error = %e, block_hash = %hash, "second chance: getblock failed; the mined case cannot be ruled out for this verdict");
                    return WalkCoverage::Failed {
                        txids: collected,
                        blocks_scanned: scanned,
                        tip_height,
                        error: e.to_string(),
                    };
                }
            };
            if tip_height.is_none() {
                tip_height = Some(block.height);
            }
            if block.height < template_height {
                // The tip has not advanced past the template's parent,
                // so nothing has been mined since the template was
                // built. This is the steady state and it is COMPLETE
                // coverage, not a shortfall.
                return WalkCoverage::Complete {
                    txids: collected,
                    blocks_scanned: scanned,
                    tip_height,
                };
            }
            collected.extend(block.txids);
            scanned = scanned.saturating_add(1);

            // Heights decrease by exactly one per step, so once this
            // block IS the template's height there is provably nothing
            // below it left to want. Deciding that here, before the cap,
            // is what stops the cap reporting a truncation that lost
            // nothing: the old order tripped `truncated` at a tip gap of
            // 5, where the sixth block was the last one needed and the
            // walk was in fact complete.
            if block.height == template_height {
                return WalkCoverage::Complete {
                    txids: collected,
                    blocks_scanned: scanned,
                    tip_height,
                };
            }
            let Some(prev) = block.previous_block_hash else {
                // Genesis. Nothing below it exists, so the walk covered
                // everything there was.
                return WalkCoverage::Complete {
                    txids: collected,
                    blocks_scanned: scanned,
                    tip_height,
                };
            };
            if scanned >= MAX_RECENT_BLOCKS_SCANNED {
                return WalkCoverage::Truncated {
                    txids: collected,
                    blocks_scanned: scanned,
                    tip_height,
                };
            }
            hash = prev;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn txid(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn answer(mempool: &[u8], blocks: &[u8]) -> BitcoindAnswer {
        BitcoindAnswer {
            present_in_mempool: mempool.iter().copied().map(txid).collect(),
            unadjudicated: HashSet::new(),
            recent_block_txids: blocks.iter().copied().map(txid).collect(),
            blocks_scanned: u32::from(!blocks.is_empty()),
            block_walk_truncated: false,
            tip_height: None,
            block_walk_shortfall: None,
        }
    }

    /// The live Setup B case, reproduced: `log_id=2952` rejected with
    /// 187 of 2738 unknown (6.83%, over the 4.0 threshold), and 10 of
    /// 10 sampled txids were in bitcoind's mempool seconds later. With
    /// every unknown held by the node the recomputed count is zero and
    /// the rejection must be withdrawn.
    #[test]
    fn unknowns_held_by_bitcoind_withdraw_the_rejection() {
        let unknown: Vec<[u8; 32]> = (1u8..=187).map(txid).collect();
        let mempool: Vec<u8> = (1u8..=187).collect();
        let adj = adjudicate(2738, &unknown, &answer(&mempool, &[]));

        assert_eq!(adj.unknown_before, 187);
        assert_eq!(adj.in_mempool, 187);
        assert_eq!(adj.still_absent, 0);
        assert!(
            !adj.still_exceeds(4.0),
            "every unknown was in bitcoind's mempool; the rejection must not stand"
        );
    }

    /// The mined case named in PB-40: a transaction selected into the
    /// template and mined before the check is known, not absent.
    #[test]
    fn unknowns_mined_since_the_template_withdraw_the_rejection() {
        let unknown: Vec<[u8; 32]> = (1u8..=50).map(txid).collect();
        let blocks: Vec<u8> = (1u8..=50).collect();
        let adj = adjudicate(100, &unknown, &answer(&[], &blocks));

        assert_eq!(adj.mined, 50);
        assert_eq!(adj.in_mempool, 0);
        assert_eq!(adj.still_absent, 0);
        assert!(
            !adj.still_exceeds(4.0),
            "a template tx mined between construction and the check is known"
        );
    }

    /// The mechanism must not become a blanket amnesty. Transactions
    /// bitcoind genuinely does not know still count, and still reject.
    #[test]
    fn genuinely_absent_unknowns_keep_the_rejection() {
        let unknown: Vec<[u8; 32]> = (1u8..=20).map(txid).collect();
        // Only 5 of the 20 are accounted for.
        let adj = adjudicate(100, &unknown, &answer(&[1, 2, 3], &[4, 5]));

        assert_eq!(adj.in_mempool, 3);
        assert_eq!(adj.mined, 2);
        assert_eq!(adj.still_absent, 15);
        assert!(
            adj.still_exceeds(4.0),
            "15 of 100 unknown is 15%, still over the 4% tolerance"
        );
    }

    /// Partial recovery across the threshold is the interesting edge:
    /// enough unknowns are explained to bring the ratio back under
    /// tolerance, and the template is accepted on the recomputed count.
    #[test]
    fn partial_recovery_below_tolerance_withdraws_the_rejection() {
        let unknown: Vec<[u8; 32]> = (1u8..=10).map(txid).collect();
        // 7 explained, 3 still absent: 3 of 100 is 3%, under 4%.
        let adj = adjudicate(100, &unknown, &answer(&[1, 2, 3, 4], &[5, 6, 7]));

        assert_eq!(adj.still_absent, 3);
        assert!(!adj.still_exceeds(4.0));
    }

    /// The first pass and the recompute must agree on the threshold
    /// rule, including at the boundary where `>` and `>=` differ.
    /// Exactly 4 of 100 is 4.0%, which is NOT over a 4.0 tolerance.
    #[test]
    fn threshold_rule_matches_the_first_pass_at_the_boundary() {
        assert!(
            !exceeds_tolerance(4, 100, 4.0),
            "exactly at tolerance is not over it"
        );
        assert!(exceeds_tolerance(5, 100, 4.0));
        assert!(
            !exceeds_tolerance(0, 0, 4.0),
            "an empty template cannot exceed a ratio"
        );
    }

    /// A reviewer at T+7 needs the identities, but bounded.
    #[test]
    fn absent_sample_is_capped_and_holds_only_the_absent() {
        let unknown: Vec<[u8; 32]> = (1u8..=100).map(txid).collect();
        let mempool: Vec<u8> = (1u8..=10).collect();
        let adj = adjudicate(200, &unknown, &answer(&mempool, &[]));

        assert_eq!(adj.still_absent, 90);
        assert_eq!(adj.still_absent_sample.len(), ABSENT_SAMPLE_CAP);
        for t in &adj.still_absent_sample {
            assert!(
                !adj_contains(&mempool, t),
                "an explained txid must never appear in the absent sample"
            );
        }
    }

    fn adj_contains(mempool: &[u8], t: &[u8; 32]) -> bool {
        mempool.iter().copied().map(txid).any(|m| m == *t)
    }

    /// Only a complete walk can support "this was not mined". The
    /// three shapes used to be indistinguishable in the record, so a
    /// verdict could claim a completed adjudication on a check that
    /// errored.
    #[test]
    fn only_a_complete_walk_is_evidence_of_absence() {
        let complete = WalkCoverage::Complete {
            txids: HashSet::new(),
            blocks_scanned: 0,
            tip_height: Some(101),
        };
        let truncated = WalkCoverage::Truncated {
            txids: HashSet::new(),
            blocks_scanned: MAX_RECENT_BLOCKS_SCANNED,
            tip_height: Some(200),
        };
        let failed = WalkCoverage::Failed {
            txids: HashSet::new(),
            blocks_scanned: 0,
            tip_height: None,
            error: "getbestblockhash: work queue depth exceeded".to_string(),
        };

        assert!(complete.is_complete());
        assert!(!truncated.is_complete());
        assert!(!failed.is_complete());

        // The shortfall is what the durable record carries, and it is
        // what makes a failed walk distinguishable from a healthy one
        // that had nothing to scan. Both report blocks_scanned == 0.
        assert_eq!(complete.shortfall(), None);
        assert!(truncated.shortfall().is_some());
        assert!(failed.shortfall().is_some());
        assert_eq!(complete.blocks_scanned_for_test(), 0);
        assert_eq!(failed.blocks_scanned_for_test(), 0);
        assert_ne!(
            complete.shortfall(),
            failed.shortfall(),
            "a healthy zero-block walk and a failed one must not look the same"
        );
    }

    /// A transaction cannot be in the mempool and mined at once; if
    /// both sets carry it the mempool answer wins and it is counted
    /// once, never twice.
    #[test]
    fn a_txid_in_both_sets_is_counted_once() {
        let unknown = [txid(1)];
        let adj = adjudicate(10, &unknown, &answer(&[1], &[1]));

        assert_eq!(adj.in_mempool, 1);
        assert_eq!(adj.mined, 0);
        assert_eq!(adj.still_absent, 0);
        assert_eq!(
            adj.in_mempool + adj.mined + adj.still_absent,
            adj.unknown_before
        );
    }

    /// The four counts are DISJOINT and must sum to the input. Without
    /// this, a reviewer or a dashboard can double-count `unadjudicated`
    /// inside `still_absent` and read an unestablished count as
    /// evidence.
    #[test]
    fn the_four_counts_are_disjoint_and_sum_to_the_unknown_set() {
        let unknown: Vec<[u8; 32]> = (1u8..=20).map(txid).collect();
        let mut a = answer(&[1, 2, 3], &[4, 5]);
        a.unadjudicated = [6u8, 7].iter().copied().map(txid).collect();
        let adj = adjudicate(100, &unknown, &a);

        assert_eq!(adj.in_mempool, 3);
        assert_eq!(adj.mined, 2);
        assert_eq!(adj.unadjudicated, 2);
        assert_eq!(adj.still_absent, 13, "proven absent only");
        assert_eq!(
            adj.in_mempool + adj.mined + adj.unadjudicated + adj.still_absent,
            adj.unknown_before
        );
    }

    /// `not_proven_known` is what the decision uses: proven absent plus
    /// the ones nobody established. `still_absent` alone would treat an
    /// unestablished transaction as known, which is the optimistic
    /// direction and the wrong one.
    #[test]
    fn unadjudicated_counts_against_recovery_not_for_it() {
        let unknown: Vec<[u8; 32]> = (1u8..=10).map(txid).collect();
        // 7 proven present, 3 unadjudicated, 0 proven absent.
        let mut a = answer(&[1, 2, 3, 4, 5, 6, 7], &[]);
        a.unadjudicated = [8u8, 9, 10].iter().copied().map(txid).collect();
        let adj = adjudicate(100, &unknown, &a);

        assert_eq!(adj.still_absent, 0);
        assert_eq!(adj.unadjudicated, 3);
        assert_eq!(adj.not_proven_known(), 3);
        assert!(
            !adj.still_exceeds(4.0),
            "3 of 100 is under the 4% tolerance even counting the unproven pessimistically"
        );

        // Now push the unproven count over the line: 5 of 100 is 5%.
        let unknown: Vec<[u8; 32]> = (1u8..=10).map(txid).collect();
        let mut a = answer(&[1, 2, 3, 4, 5], &[]);
        a.unadjudicated = [6u8, 7, 8, 9, 10].iter().copied().map(txid).collect();
        let adj = adjudicate(100, &unknown, &a);
        assert_eq!(adj.still_absent, 0, "none were PROVEN absent");
        assert!(
            adj.still_exceeds(4.0),
            "five unestablished transactions must not be read as recovered"
        );
    }

    /// Precedence: present beats mined beats unadjudicated beats absent,
    /// and a txid in several sets is counted exactly once.
    #[test]
    fn classification_precedence_counts_each_txid_once() {
        let unknown = [txid(1)];
        let mut a = answer(&[1], &[1]);
        a.unadjudicated = [txid(1)].into_iter().collect();
        let adj = adjudicate(10, &unknown, &a);

        assert_eq!(adj.in_mempool, 1);
        assert_eq!(adj.mined, 0);
        assert_eq!(adj.unadjudicated, 0);
        assert_eq!(adj.still_absent, 0);
        assert_eq!(adj.unknown_before, 1);
    }
}
