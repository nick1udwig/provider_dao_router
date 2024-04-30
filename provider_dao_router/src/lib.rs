use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use alloy_primitives::Address as AlloyAddress;
use alloy_sol_types::{sol, SolEvent};
use rand::{Rng, SeedableRng, prelude::SliceRandom};
use rand_pcg::Pcg64;
use serde::{Deserialize, Serialize};

use kinode_process_lib::{await_message, call_init, get_blob, get_typed_state, println, set_state, eth, Address, LazyLoadBlob, Message, ProcessId, Request, Response, SendError};

wit_bindgen::generate!({
    path: "wit",
    world: "process",
});

const CHAIN_ID: u64 = 10; // optimism
const CONTRACT_ADDRESS: &str = "0xfoobar"; // optimism TODO
const EVENTS: [&str; 8] = [
    "DaoCreated(bytes32)",
    "DaoDestroyed(bytes32)",
    "MemberAdded(bytes32,address,bytes32,bool,bool)",
    "MemberChanged(bytes32,address,bytes32,bool,bool,bool)",
    "ParametersChanged(bytes32,uint256,uint256,uint256)",
    "IsPermissionedChanged(bytes32,bool)",
    "ProposalCreated(bytes32,uint256)",
    "Voted(bytes32,address,uint256,bool)",
];
const SAVE_STATE_EVERY_N_BLOCKS: u64 = 1000;

sol! {
    event DaoCreated(bytes32 daoId);
    event DaoDestroyed(bytes32 daoId);
    event MemberAdded(bytes32 daoId, address member, bytes32 nodeId, bool isProvider, bool isRouter);
    event MemberChanged(
        bytes32 daoId,
        address member,
        bytes32 nodeId,
        bool isMember,
        bool isProvider,
        bool isRouter
    );
    event ParametersChanged(
        bytes32 daoId,
        uint256 queueResponseTimeoutSeconds,
        uint256 serveTimeoutSeconds,
        uint256 maxOutstandingPayments
    );
    event IsPermissionedChanged(bytes32 daoId, bool isPermissioned);
    event ProposalCreated(bytes32 daoId, uint256 proposalId);
    event Voted(bytes32 daoId, address voter, uint256 proposalId, bool vote);
}

#[derive(Debug, Serialize, Deserialize)]
enum PublicRequest {
    RunJob(JobParameters),
    /// Parameters in LazyLoadBlob.
    JobUpdate { job_id: u64, is_final: bool, signature: Result<u64, String> },
}

#[derive(Debug, Serialize, Deserialize)]
enum PublicResponse {
    RunJob(RunResponse),
    JobUpdate,
}

#[derive(Debug, Serialize, Deserialize)]
enum MemberRequest {
    SetIsReady { is_ready: bool },
    /// Router querying if member is ready to serve.
    QueryReady,
    JobTaken { job_id: u64 },
    ServeJob { job_id: u64, seed: u32, workflow: String, parameters: String },
    ///// Job result.
    ///// Signature in body; result in LazyLoadBlob.
    JobUpdate { job_id: u64, is_final: bool, signature: Result<u64, String> },
}

#[derive(Debug, Serialize, Deserialize)]
enum MemberResponse {
    SetIsReady,
    /// Member Response to router: is_ready.
    QueryReady { is_ready: bool },
    /// Ack
    JobTaken,
    //ServeJob { job_id: u64, signature: Result<u64, String> },  // ?
    /// Ack
    ServeJob,
    /// Ack
    JobUpdate,
}

#[derive(Debug, Serialize, Deserialize)]
enum AdminRequest {
    SetProviderProcess { process_id: String },
    SetRollupSequencer { address: String },
    SetContractAddress { address: String },
    CreateDao,
    SetDaoId { dao_id: Vec<u8> },
}

#[derive(Debug, Serialize, Deserialize)]
enum AdminResponse {
    SetProviderProcess { err: Option<String> },
    SetRollupSequencer { err: Option<String> },
    SetContractAddress { err: Option<String> },
    CreateDao { err: Option<String> },
    SetDaoId { err: Option<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum SequencerRequest {
    Read(ReadRequest),
    //Write(SignedTransaction<OnChainDaoState>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum SequencerResponse {
    Read(ReadResponse),
    Write,  // TODO: return hash of tx?
}

#[derive(Debug, Serialize, Deserialize)]
enum RunResponse {
    JobQueued { job_id: u64 },
    PaymentRequired,
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JobParameters {
    pub workflow: String,
    pub parameters: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum ReadRequest {
    All,
    Dao,
    Routers,
    Members,
    Proposals,
    Parameters,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum ReadResponse {
    All(OnChainDaoState),
    Dao,
    Routers(Vec<String>),  // length 1 for now
    Members(Vec<String>),  // TODO: should probably be the HashMap
    Proposals,
    Parameters,
}

#[derive(Debug, Serialize, Deserialize)]
struct FullDaoState {
    provider_process: Option<ProcessId>,
    rollup_sequencer: Option<Address>,
    on_chain_state: OnChainDaoState,
    ready_providers: HashSet<String>,
    outstanding_jobs: HashMap<String, (Address, u64)>,
    job_queue: std::collections::VecDeque<(Address, u64, JobParameters)>,
    job_queries: HashMap<u64, JobQuery>,
    rng: Pcg64,
    contract_address: String,
    last_saved_block: u64,
    dao_id: Vec<u8>,
    // TODO: payments
    // client_outstanding_payments: HashMap<String, u8>,
    // alleged_receipts: HashMap<>,
    // unpaid_receipts: HashMap<>,
    // pending_receipts: HashMap<>,
    // paid_receipts: Vec<HashMap<>>,
}

#[derive(Debug, Serialize, Deserialize)]
struct JobQuery {
    job: JobParameters,
    num_rejections: u32,
    num_queried: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct OnChainDaoState {
    pub routers: Vec<String>,  // length 1 for now
    pub members: HashMap<String, AlloyAddress>,
    pub proposals: HashMap<u64, ProposalInProgress>,
    // pub client_blacklist: Vec<String>,
    // pub member_blacklist: Vec<String>,
    pub queue_response_timeout_seconds: u8,
    pub serve_timeout_seconds: u16, // TODO
    pub max_outstanding_payments: u8,
    // pub payment_period_hours: u8,
    pub is_permissioned: bool,
}

/// Possible proposals
#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum Proposal {
    ChangeRootNode(String),
    ChangeQueueResponseTimeoutSeconds(u8),
    ChangeMaxOutstandingPayments(u8),
    ChangePaymentPeriodHours(u8),
    Kick(String),
}

/// Possible proposals
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProposalInProgress {
    pub proposal: Proposal,
    pub votes: HashMap<String, SignedVote>,
}

/// A vote on a proposal
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Vote {
    pub proposal_hash: u64,
    pub is_yea: bool,
}

/// A signed vote on a proposal
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignedVote {
    vote: Vote,
    signature: u64,
}

impl Default for FullDaoState {
    fn default() -> Self {
        Self {
            provider_process: None,
            rollup_sequencer: None,
            on_chain_state: OnChainDaoState::default(),
            ready_providers: HashSet::new(),
            outstanding_jobs: HashMap::new(),
            job_queue: std::collections::VecDeque::new(),
            job_queries: HashMap::new(),
            rng: Pcg64::from_entropy(),
            contract_address: CONTRACT_ADDRESS.to_string(),
            last_saved_block: 0,
            dao_id: vec![],
        }
    }
}

impl Default for OnChainDaoState {
    fn default() -> Self {
        // TODO: get state from rollup
        Self {
            routers: vec![],
            members: HashMap::new(),
            proposals: HashMap::new(),
            queue_response_timeout_seconds: 1,  // NOTE: default
            serve_timeout_seconds: 60,          // NOTE: default
            max_outstanding_payments: 3,        // NOTE: default
            //payment_period_hours: 0,
            is_permissioned: true,
        }
    }
}

impl FullDaoState {
    fn save(&self) -> anyhow::Result<()> {
        set_state(&serde_json::to_vec(self)?);
        Ok(())
    }

    fn load() -> Self {
        match get_typed_state(|bytes| Ok(serde_json::from_slice::<FullDaoState>(bytes)?)) {
            Some(rs) => rs,
            None => FullDaoState::default(),
        }
    }

    fn ingest_listings_contract_event(
        &mut self,
        our: &Address,
        log: eth::Log,
    ) -> anyhow::Result<()> {
        match log.topics[0] {
            DaoCreated::SIGNATURE_HASH => {
                let dao_id = DaoCreated::abi_decode_data(&log.data, true)?.0.to_vec();
                if dao_id == self.dao_id {
                    println!("got dao creation event");
                }
            }
            DaoDestroyed::SIGNATURE_HASH => {
                let dao_id = DaoDestroyed::abi_decode_data(&log.data, true)?.0.to_vec();
                if dao_id != self.dao_id {
                    return Ok(());
                }
                println!("got dao destruction event");
                self.on_chain_state = OnChainDaoState::default();
                self.dao_id = vec![];
            }
            MemberAdded::SIGNATURE_HASH => {
                let (dao_id, member, node_id, is_provider, is_router) = MemberAdded::abi_decode_data(&log.data, true)?;
                if dao_id.to_vec() != self.dao_id {
                    return Ok(());
                }
                let node_id = node_id.to_vec();
                let node = String::from_utf8(node_id)?;
                if is_provider {
                    self.on_chain_state.members.insert(node.clone(), member);
                }
                if is_router {
                    self.on_chain_state.routers.push(node);
                }
                self.on_chain_state.queue_response_timeout_seconds = 1;  // NOTE: hardcode
                self.on_chain_state.serve_timeout_seconds = 60;          // NOTE: hardcode
                self.on_chain_state.max_outstanding_payments = 3;        // NOTE: hardcode
            }
            MemberChanged::SIGNATURE_HASH => {
                let (dao_id, member, node_id, is_member, is_provider, is_router) = MemberChanged::abi_decode_data(&log.data, true)?;
                if dao_id.to_vec() != self.dao_id {
                    return Ok(());
                }
                let node_id = node_id.to_vec();
                let node = String::from_utf8(node_id)?;
                if !is_member {
                    self.on_chain_state.members.remove(&node);
                    if let Some(pos) = self.on_chain_state.routers.iter().position(|s| s == &node) {
                        self.on_chain_state.routers.remove(pos);
                    }
                    return Ok(());
                }
                if is_provider {
                    self.on_chain_state.members.insert(node.clone(), member);
                } else {
                    self.on_chain_state.members.remove(&node);
                }
                if is_router {
                    if !self.on_chain_state.routers.contains(&node) {
                        self.on_chain_state.routers.push(node);
                    }
                } else {
                    if let Some(pos) = self.on_chain_state.routers.iter().position(|s| s == &node) {
                        self.on_chain_state.routers.remove(pos);
                    }
                }
            }
            ParametersChanged::SIGNATURE_HASH => {
                let (dao_id, queue_response_timeout_seconds, serve_timeout_seconds, max_outstanding_payments) = ParametersChanged::abi_decode_data(&log.data, true)?;
                if dao_id.to_vec() != self.dao_id {
                    return Ok(());
                }
                self.on_chain_state.queue_response_timeout_seconds = u8::try_from(queue_response_timeout_seconds)?;
                self.on_chain_state.serve_timeout_seconds = u16::try_from(serve_timeout_seconds)?;
                self.on_chain_state.max_outstanding_payments = u8::try_from(max_outstanding_payments)?;
            }
            IsPermissionedChanged::SIGNATURE_HASH => {
                let (dao_id, is_permissioned) = IsPermissionedChanged::abi_decode_data(&log.data, true)?;
                if dao_id.to_vec() != self.dao_id {
                    return Ok(());
                }
                self.on_chain_state.is_permissioned = is_permissioned;
            }
            ProposalCreated::SIGNATURE_HASH => {
                let (dao_id, proposal_id) = ProposalCreated::abi_decode_data(&log.data, true)?;
                if dao_id.to_vec() != self.dao_id {
                    return Ok(());
                }
                // TODO
            }
            Voted::SIGNATURE_HASH => {
                let (dao_id, voter, proposal_id, vote) = Voted::abi_decode_data(&log.data, true)?;
                if dao_id.to_vec() != self.dao_id {
                    return Ok(());
                }
                // TODO
            }
            _ => {}
        }
        let block_number: u64 = log
            .block_number
            .ok_or(anyhow::anyhow!("got log with no block number"))?
            .try_into()?;
        if block_number > self.last_saved_block + SAVE_STATE_EVERY_N_BLOCKS {
            self.last_saved_block = block_number;
            self.save()?;
        }
        Ok(())
    }
}

fn permute<T>(mut vec: Vec<T>, rng: &mut Pcg64) -> Vec<T> {
    vec.shuffle(rng);
    vec
}

// fn permute_and_chunk<T>(mut vec: Vec<T>, chunk_size: usize) -> Vec<Vec<T>> {
//     let mut rng = rand::thread_rng();
//     vec.shuffle(&mut rng);
//
//     vec.chunks(chunk_size).map(|chunk| chunk.to_vec()).collect()
// }

// fn fetch_chain_state(state: &mut FullDaoState) -> anyhow::Result<()> {
//     let Some(rollup_sequencer) = state.rollup_sequencer.clone() else {
//         return Err(anyhow::anyhow!("fetch_chain_state rollup_sequencer must be set before chain state can be fetched"));
//     };
//     Request::to(rollup_sequencer)  // TODO
//         .body(vec![])
//         .blob_bytes(serde_json::to_vec(&SequencerRequest::Read(ReadRequest::All))?)
//         .expects_response(5) // TODO
//         .send()?;
//     Ok(())
// }

fn fetch_logs(eth_provider: &eth::Provider, filter: &eth::Filter) -> Vec<eth::Log> {
    loop {
        match eth_provider.get_logs(filter) {
            Ok(res) => return res,
            Err(_) => {
                println!("failed to fetch logs! trying again in 5s...");
                std::thread::sleep(std::time::Duration::from_secs(5));
                continue;
            }
        }
    }
}

fn subscribe_to_logs(eth_provider: &eth::Provider, filter: &eth::Filter) {
    loop {
        match eth_provider.subscribe(1, filter.clone()) {
            Ok(()) => break,
            Err(_) => {
                println!("failed to subscribe to chain! trying again in 5s...");
                std::thread::sleep(std::time::Duration::from_secs(5));
                continue;
            }
        }
    }
}

fn await_chain_state(state: &mut FullDaoState) -> anyhow::Result<()> {
    let Some(rollup_sequencer) = state.rollup_sequencer.clone() else {
        return Err(anyhow::anyhow!("fetch_chain_state rollup_sequencer must be set before chain state can be fetched"));
    };
    Request::to(rollup_sequencer)  // TODO
        .body(vec![])
        .blob_bytes(serde_json::to_vec(&SequencerRequest::Read(ReadRequest::All))?)
        .send_and_await_response(5)??;
    let Some(LazyLoadBlob { ref bytes, .. }) = get_blob() else {
        return Err(anyhow::anyhow!("fetch_chain_state didn't get back blob"));
    };
    let Ok(SequencerResponse::Read(ReadResponse::All(new_dao_state))) = serde_json::from_slice(bytes) else {
        //println!("{:?}", serde_json::from_slice::<serde_json::Value>(bytes));
        return Err(anyhow::anyhow!("fetch_chain_state got wrong Response back"));
    };
    state.on_chain_state = new_dao_state.clone();
    state.save()?;
    Ok(())
}

fn serve_job(
    member: &Address,
    job_source: &Address,
    job_id: u64,
    job: JobParameters,
    state: &mut FullDaoState,
) -> anyhow::Result<()> {
     let job_id: u64 = state.rng.gen();
     state.outstanding_jobs.insert(
         member.node().to_string(),
         (job_source.clone(), job_id.clone()),
     );
     let seed = state.rng.gen_range(0..10_000_000);  // TODO
     Request::to(member)
         .body(serde_json::to_vec(&MemberRequest::ServeJob {
             job_id,
             seed,
             workflow: job.workflow,
             parameters: job.parameters,
         })?)
         .inherit(true)
         .expects_response(5)  // TODO
         .send()?;
    state.save()?;
    Ok(())
}

fn handle_admin_request(
    our: &Address,
    message: &Message,
    eth_provider: &eth::Provider,
    filter: &eth::Filter,
    state: &mut FullDaoState,
) -> anyhow::Result<()> {
    let source = message.source();
    if source.node() != our.node() {
        return Err(anyhow::anyhow!("only our can make AdminRequests; rejecting from {source:?}"));
    }
    match serde_json::from_slice(message.body())? {
        AdminRequest::SetProviderProcess { process_id } => {
            let process_id = process_id.parse()?;
            state.provider_process = Some(process_id);
            state.save()?;
            Response::new()
                .body(serde_json::to_vec(&AdminResponse::SetProviderProcess { err: None })?)
                .send()?;
        }
        AdminRequest::SetRollupSequencer { address } => {
            let address = address.parse()?;
            state.rollup_sequencer = Some(address);
            await_chain_state(state)?;
            Response::new()
                .body(serde_json::to_vec(&AdminResponse::SetRollupSequencer { err: None })?)
                .send()?;
        }
        AdminRequest::SetContractAddress { address } => {
            state.contract_address = address;
            Response::new()
                .body(serde_json::to_vec(&AdminResponse::SetContractAddress { err: None })?)
                .send()?;
        }
        AdminRequest::CreateDao => {
            // TODO:
            // this belong on the FE, along with all other DAO-changing requests
            // so we can take advantage of already-existing wallet software
            //init_eth(our, eth_provider, filter, state).unwrap();
            //Response::new()
            //    .body(serde_json::to_vec(&AdminResponse::CreateDao { err: None })?)
            //    .send()?;
        }
        AdminRequest::SetDaoId { dao_id } => {
            state.dao_id = dao_id;
            init_eth(our, eth_provider, filter, state).unwrap();
            Response::new()
                .body(serde_json::to_vec(&AdminResponse::SetDaoId { err: None })?)
                .send()?;
        }
    }
    Ok(())
}

fn handle_public_request(
    our: &Address,
    message: &Message,
    state: &mut FullDaoState,
) -> anyhow::Result<()> {
    match serde_json::from_slice(message.body())? {
        PublicRequest::RunJob(job) => {
            let job_id: u64 = state.rng.gen();
            Response::new()
                .body(serde_json::to_vec(&PublicResponse::RunJob(RunResponse::JobQueued {
                    job_id: job_id.clone(),
                }))?)
                .send()?;
            if state.ready_providers.is_empty() {
                // no ready providers -> add to queue
                state.job_queue.push_back((message.source().clone(), job_id, job));
                println!("new job added to queue; now have {} queued", state.job_queue.len());
                state.save()?;
                return Ok(());
            }
            // permute is_ready providers & flood all with query if ready;
            //  first gets job; if none ready, queue
            // TODO: improve algo
            let process_id = state.provider_process.clone().unwrap();
            state.job_queries.insert(job_id, JobQuery {
                job: job.clone(),
                num_rejections: 0,
                num_queried: state.ready_providers.len() as u32,
            });
            for member in permute(state.ready_providers.iter().cloned().collect(), &mut state.rng) {
                let address = Address::new(member.clone(), process_id.clone());
                Request::to(address.clone())
                    .body(serde_json::to_vec(&MemberRequest::QueryReady)?)
                    .context(serde_json::to_vec(&(message.source().clone(), job_id))?)
                    .expects_response(
                        state.on_chain_state.queue_response_timeout_seconds as u64
                    )
                    .send()?;
            }
        }
        PublicRequest::JobUpdate { .. } => {
            return Err(anyhow::anyhow!("unexpected PublicRequest"));
        }
    }
    Ok(())
}

fn handle_member_request(
    our: &Address,
    message: &Message,
    state: &mut FullDaoState,
) -> anyhow::Result<()> {
    let source = message.source();
    if !state.on_chain_state.members.contains_key(source.node()) &&
       !state.on_chain_state.routers.contains(&source.node().to_string()) {
        return Err(anyhow::anyhow!(
            "only members can send member Requests; rejecting from {source:?}"
        ));
    }
    match serde_json::from_slice(message.body())? {
        MemberRequest::SetIsReady { is_ready } => {
            if !is_ready {
                state.ready_providers.remove(source.node());
                state.save()?;
            } else {
                if !state.job_queue.is_empty() {
                    let (job_source, job_id, job) = state.job_queue.pop_front().unwrap();
                    serve_job(source, &job_source, job_id, job, state)?;
                } else {
                    state.ready_providers.insert(source.node().to_string());
                    state.save()?;
                }
            }
        }
        MemberRequest::JobUpdate { ref job_id, ref is_final, ref signature } => {
            let Some((job_source, expected_job_id)) = state.outstanding_jobs.get(message.source().node()) else {
                return Err(anyhow::anyhow!("provider sent back {job_id} but no record here"));
            };
            if job_id != expected_job_id {
                println!("job_id != expected_job_id: this should never occur! provider gave us wrong job back");
            }
            Request::to(job_source)
                .body(message.body())
                .inherit(true)
                .send()?;
            // TODO: log sigs
            if is_final == &true {
                state.outstanding_jobs.remove(message.source().node());
                state.save()?;
            }
        }
        MemberRequest::QueryReady | MemberRequest::ServeJob { .. } | MemberRequest::JobTaken { .. } => {
            return Err(anyhow::anyhow!("unexpected MemberRequest"));
        }
    }
    Ok(())
}

fn handle_eth_sub(
    our: &Address,
    message: &Message,
    eth_provider: &eth::Provider,
    state: &mut FullDaoState,
) -> anyhow::Result<()> {
    let eth_sub_result = serde_json::from_slice::<eth::EthSubResult>(message.body())?;
    if message.source().node() != our.node() || message.source().process != "eth:distro:sys" {
        return Err(anyhow::anyhow!("eth sub event from weird addr: {}", message.source()));
    }
    match eth_sub_result {
        Ok(event) => {
            // handle eth sub event
            let eth::SubscriptionResult::Log(log) = event.result else {
                return Err(anyhow::anyhow!("got non-log event"));
            };
            state.ingest_listings_contract_event(our, *log)?;
        }
        Err(_e) => {
            println!("got eth subscription error");
            // attempt to resubscribe
            subscribe_to_logs(
                eth_provider,
                &eth::Filter::new()
                    .address(eth::Address::from_str(&state.contract_address).unwrap())
                    .from_block(state.last_saved_block - 1)
                    .to_block(eth::BlockNumberOrTag::Latest)
                    .events(EVENTS),
            );
        }
    }
    Ok(())
}

fn handle_member_response(
    our: &Address,
    message: &Message,
    state: &mut FullDaoState,
) -> anyhow::Result<()> {
    match serde_json::from_slice(message.body())? {
        MemberResponse::QueryReady { is_ready } => {
            // compare to handle_message() send_err case
            let (job_source, job_id): (Address, u64) = serde_json::from_slice(
                message.context().unwrap_or_default()
            )?;
            let Some(mut job_query) = state.job_queries.remove(&job_id) else {
                Request::to(message.source())
                    .body(serde_json::to_vec(&MemberRequest::JobTaken { job_id })?)
                    .send()?;
                state.save()?;
                return Ok(());
            };
            if !is_ready {
                // TODO: reprimand fake ready member?
                job_query.num_rejections += 1;
                if job_query.num_rejections >= job_query.num_queried {
                    // no one available to serve job
                    // TODO: add stat trackers so we can expose endpoints:
                    //  * how long queue is
                    //  * average time / job
                    //    -> expected time till result
                    state.job_queue.push_back((job_source, job_id.clone(), job_query.job));
                    println!("no ready providers; now have {} queued", state.job_queue.len());
                    state.save()?;
                    return Ok(());
                }
                state.job_queries.insert(job_id, job_query);
                state.save()?;
                return Ok(());
            }
            serve_job(message.source(), &job_source, job_id, job_query.job, state)?;
        }
        MemberResponse::JobTaken | MemberResponse::ServeJob => {}
        MemberResponse::SetIsReady | MemberResponse::JobUpdate => {
            return Err(anyhow::anyhow!("unexpected MemberResponse"));
        }
    }
    Ok(())
}

fn handle_sequencer_response(state: &mut FullDaoState) -> anyhow::Result<()> {
    let Some(LazyLoadBlob { ref bytes, .. }) = get_blob() else {
        return Err(anyhow::anyhow!("fetch_chain_state didn't get back blob"));
    };
    let Ok(SequencerResponse::Read(ReadResponse::All(new_dao_state))) = serde_json::from_slice(bytes) else {
        return Err(anyhow::anyhow!("fetch_chain_state got wrong Response back"));
    };
    state.on_chain_state = new_dao_state.clone();
    state.save()?;
    Ok(())
}

fn handle_message(
    our: &Address,
    state: &mut FullDaoState,
    eth_provider: &eth::Provider,
    filter: &eth::Filter,
) -> anyhow::Result<()> {
    let message = match await_message() {
        Ok(m) => m,
        Err(send_err) => {
            //println!("SendError\nkind: {:?}\nbody: {:?}", send_err.kind(), serde_json::from_slice::<serde_json::Value>(send_err.message().body()));
            // compare to handle_member_response() MemberResponse::QueryReady case
            let (source, job_id): (Address, u64) = serde_json::from_slice(
                send_err.context().unwrap_or_default()
            )?;
            let Some(mut job_query) = state.job_queries.remove(&job_id) else {
                // provider is offline, so don't inform them
                return Ok(());
            };
            job_query.num_rejections += 1;
            if job_query.num_rejections >= job_query.num_queried {
                // no one available to serve job
                // TODO: add stat trackers so we can expose endpoints:
                //  * how long queue is
                //  * average time / job
                //    -> expected time till result
                state.job_queue.push_back((source, job_id, job_query.job));
                println!("no ready providers; now have {} queued", state.job_queue.len());
                state.save()?;
                return Ok(());
            }
            state.job_queries.insert(job_id, job_query);
            state.save()?;
            return Ok(());
        }
    };

    if message.is_request() {
        if handle_admin_request(our, &message, eth_provider, filter, state).is_ok() {
            return Ok(());
        }
        if handle_eth_sub(our, &message, eth_provider, state).is_ok() {
            return Ok(());
        }
        if state.provider_process.is_none() {
            return Err(anyhow::anyhow!(
                "provider package must be set by AdminRequest before accepting other Requests"
            ));
        }
        if state.rollup_sequencer.is_none() {
            return Err(anyhow::anyhow!(
                "rollup sequencer must be set by AdminRequest before accepting other Requests"
            ));
        }
        if handle_public_request(our, &message, state).is_ok() {
            return Ok(());
        }
        return handle_member_request(our, &message, state);
    }

    if handle_sequencer_response(state).is_ok() {
        return Ok(());
    };
    handle_member_response(our, &message, state)?;

    Ok(())
}

fn init_eth(
    our: &Address,
    eth_provider: &eth::Provider,
    filter: &eth::Filter,
    state: &mut FullDaoState,
) -> anyhow::Result<()> {
    for log in fetch_logs(&eth_provider, &filter) {
        if let Err(e) = state.ingest_listings_contract_event(our, log) {
            println!("error ingesting log: {e:?}");
        };
    }
    subscribe_to_logs(&eth_provider, filter);
    Ok(())
}

call_init!(init);
fn init(our: Address) {
    println!("begin");

    let mut state = FullDaoState::load();
    println!("contract_address, dao_id: {}, {:?}", state.contract_address, state.dao_id);

    // create new provider for sepolia with request-timeout of 60s
    // can change, log requests can take quite a long time.
    let eth_provider = eth::Provider::new(CHAIN_ID, 60);

    // get past logs, subscribe to new ones.
    let filter = eth::Filter::new()
        .address(eth::Address::from_str(&state.contract_address).unwrap())
        .from_block(state.last_saved_block - 1)
        .to_block(eth::BlockNumberOrTag::Latest)
        .events(EVENTS);

    if !state.dao_id.is_empty() {
        init_eth(&our, &eth_provider, &filter, &mut state).unwrap();
    }

    loop {
        match handle_message(&our, &mut state, &eth_provider, &filter) {
            Ok(()) => {},
            Err(e) => println!("{}: error: {:?}", our.process(), e),
        };
    }
}
