//! Read-only inventory of the committed committee session of app shards:
//! every member's prover address and registry record, so a session's silent
//! members can be named. Opens a running node's master store as a read-only
//! point-in-time view; writes nothing.
//!
//! usage: committee_inventory MASTER_STORE FILTER_HEX...
use std::{path::PathBuf, sync::Arc};

use quil_engine::app_handoff::SessionChoice;
use quil_types::store::ClockStore;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        return Err("usage: committee_inventory MASTER_STORE FILTER_HEX...".into());
    }
    quil_crypto::init();
    quil_types::consensus::init_committee_handoff_for_network(0);
    let db = quil_store::RocksDb::open_for_read_only_live(&PathBuf::from(&args[0]))?;
    let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
    let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
        store.clone() as Arc<dyn quil_types::store::HypergraphStore>,
        Arc::new(quil_types::crypto::NoopInclusionProver),
    ));
    crdt.set_forest(quil_forest::Forest::with_namespace(db.inner(), quil_store::FOREST_NAMESPACE));
    let clock = quil_store::RocksClockStore::new(db.inner());
    let head = clock.get_latest_global_clock_frame().ok().and_then(|f| f.header.map(|h| h.frame_number)).unwrap_or(0);
    let mut registry = quil_execution::prover_registry::InMemoryProverRegistry::new();
    registry.refresh(store.as_ref())?;
    println!("{}", serde_json::json!({"kind": "head", "global_frame": head,
        "distinct_provers": registry.distinct_provers()}));
    for filter_hex in &args[1..] {
        let filter = hex::decode(filter_hex)?;
        let session = match quil_engine::app_handoff::resolve(&crdt, &filter, head)? {
            SessionChoice::Session(session) => session,
            SessionChoice::Pending(reason) => {
                println!("{}", serde_json::json!({"kind": "pending", "filter": filter_hex, "reason": reason}));
                continue;
            }
            SessionChoice::Legacy => {
                println!("{}", serde_json::json!({"kind": "legacy", "filter": filter_hex}));
                continue;
            }
        };
        println!("{}", serde_json::json!({"kind": "session", "filter": filter_hex,
            "generation": session.generation, "base_frame": session.base_frame,
            "members": session.members.len(), "session": hex::encode(session.id()?)}));
        for (index, key) in session.members.iter().enumerate() {
            let address = quil_execution::global_intrinsic::materialize::prover_address_from_pubkey(key)?;
            let mut row = serde_json::json!({"kind": "member", "filter": filter_hex,
                "index": index, "address": hex::encode(address)});
            if let Some(info) = registry.get_prover_info(&address) {
                let here = info.allocations.iter().find(|a| a.confirmation_filter == filter);
                let statuses = info.allocations.iter().fold(std::collections::BTreeMap::<String, u64>::new(), |mut m, a| {
                    *m.entry(format!("{:?}", a.status)).or_default() += 1;
                    m
                });
                row["prover_status"] = format!("{:?}", info.status).into();
                row["seniority"] = info.seniority.into();
                row["allocations"] = serde_json::to_value(&statuses)?;
                row["max_last_active"] = info.allocations.iter().map(|a| a.last_active_frame_number).max().unwrap_or(0).into();
                if let Some(a) = here {
                    row["here"] = serde_json::json!({"status": format!("{:?}", a.status), "epoch": a.epoch,
                        "join": a.join_frame_number, "join_confirm": a.join_confirm_frame_number,
                        "last_active": a.last_active_frame_number, "leave": a.leave_frame_number,
                        "pause": a.pause_frame_number, "kick": a.kick_frame_number});
                }
            }
            println!("{row}");
        }
    }
    Ok(())
}
