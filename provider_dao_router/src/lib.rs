use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use alloy_primitives::Address as AlloyAddress;
use rand::{Rng, SeedableRng, prelude::SliceRandom};
use rand_pcg::Pcg64;
use serde::{Deserialize, Serialize};

use kinode_process_lib::{await_message, call_init, get_blob, get_typed_state, println, set_state, Address, LazyLoadBlob, Message, ProcessId, Request, Response, SendError};

wit_bindgen::generate!({
    path: "wit",
    world: "process",
    exports: {
        world: Component,
    },
});

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
}

#[derive(Debug, Serialize, Deserialize)]
enum AdminResponse {
    SetProviderProcess { err: Option<String> },
    SetRollupSequencer { err: Option<String> },
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
    pub payment_period_hours: u8,
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
            queue_response_timeout_seconds: 0,
            serve_timeout_seconds: 0,
            max_outstanding_payments: 0,
            payment_period_hours: 0,
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
        println!("{:?}", serde_json::from_slice::<serde_json::Value>(bytes));
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
     let seed = state.rng.gen_range(0..1_000_000);  // TODO
     Request::to(member)
         .body(serde_json::to_vec(&MemberRequest::ServeJob {
             job_id,
             seed,
             workflow: job.workflow,
             parameters: job.parameters,
         })?)
         .inherit(true)
         .expects_response(60)  // TODO
         .send()?;
    state.save()?;
    Ok(())
}

fn handle_admin_request(
    our: &Address,
    message: &Message,
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
            if !state.job_queue.is_empty() {
                // other jobs in queue -> add to back
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
            if is_ready {
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

fn handle_member_response(
    our: &Address,
    message: &Message,
    state: &mut FullDaoState,
) -> anyhow::Result<()> {
    match serde_json::from_slice(message.body())? {
        //MemberResponse::ServeJob { job_id, signature } => {
            //if let Err(e) = signature {
            //    return Err(anyhow::anyhow!("{}", e));
            //}
            //// give Response to client
            //Response::new()
            //    .body(serde_json::to_vec(&PublicResponse::RunJob(RunResponse::JobComplete))?)
            //    .inherit(true)
            //    .send()?;
            //let Some((job_source, expected_job_id)) = state.outstanding_jobs.remove(message.source().node()) else {
            //    return Err(anyhow::anyhow!("provider sent back {job_id} but no record here"));
            //};
            //if job_id != expected_job_id {
            //    println!("job_id != expected_job_id: this should never occur! provider gave us wrong job back");
            //}
            //state.save()?;
        //}
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

fn handle_message(our: &Address, state: &mut FullDaoState) -> anyhow::Result<()> {
    let message = match await_message() {
        Ok(m) => m,
        Err(send_err) => {
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
        if handle_admin_request(our, &message, state).is_ok() {
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

call_init!(init);
fn init(our: Address) {
    println!("begin");

    let mut state = FullDaoState::load();

    loop {
        match handle_message(&our, &mut state) {
            Ok(()) => {},
            Err(e) => println!("{}: error: {:?}", our.process(), e),
        };
    }
}
