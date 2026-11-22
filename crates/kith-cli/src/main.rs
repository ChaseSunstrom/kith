//! `kith`: the command line for kith.
//!
//! Commands talk to kithd over its unix socket, or with `--server` over TLS to a node
//! (cargo feature `remote`), or with `--store` work on a store file directly (no daemon,
//! nothing runs).

use clap::{Args, Parser, Subcommand, ValueEnum};
use kith_api::store::{self, Action, Change, FileStore, Revision, Store, rfc3339};
use kith_api::{DEFAULT_NAMESPACE, KINDS, Resource};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

mod context;
#[cfg(feature = "docker")]
mod docker_store;
mod import;
mod launch;
mod machine;
mod remote;
mod signing;
mod ui;
mod wire;

use wire::{Route, Wire};

#[derive(Parser)]
#[command(
    name = "kith",
    version,
    about = "Configure a kith cluster through declarative resources"
)]
struct Cli {
    /// kithd's socket [default: $XDG_RUNTIME_DIR/kith/kithd.sock, or /run/kith/kithd.sock]
    #[arg(long, env = "KITH_SOCKET", global = true, value_name = "PATH")]
    socket: Option<PathBuf>,
    /// Give up when kithd has not answered for this many seconds
    #[arg(
        long,
        env = "KITH_TIMEOUT",
        global = true,
        value_name = "SECONDS",
        default_value_t = 30,
        value_parser = clap::value_parser!(u64).range(1..)
    )]
    timeout: u64,
    /// Work on a store file directly instead of talking to kithd (wins over --server and --socket)
    #[arg(long, env = "KITH_STORE", global = true, value_name = "FILE")]
    store: Option<PathBuf>,
    /// kithd on a node, over TLS: the node's --listen address (wins over --socket; needs --identity)
    #[arg(long, env = "KITH_SERVER", global = true, value_name = "HOST:PORT")]
    server: Option<String>,
    /// The identity directory to show the node: its ca.crt, and NAME.crt with NAME.key
    #[arg(long, env = "KITH_IDENTITY", global = true, value_name = "DIR")]
    identity: Option<PathBuf>,
    /// Take --server and --identity from this entry of `kith context ls` (a flag still wins)
    #[arg(long, env = "KITH_CONTEXT", global = true, value_name = "NAME")]
    context: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create or update resources from files
    Apply {
        #[command(flatten)]
        files: Files,
        /// Show what would happen without changing anything
        #[arg(long)]
        dry_run: bool,
    },
    /// Show what `apply` would change; exits 1 if there are changes
    Diff {
        #[command(flatten)]
        files: Files,
    },
    /// Check files without touching the store
    Lint {
        #[command(flatten)]
        files: Files,
    },
    /// Print what a `.kith` file gives, as YAML
    Eval {
        /// A file in kith's own language
        file: PathBuf,
    },
    /// List resources, or show one
    Get {
        /// KIND or KIND/NAME; everything when omitted
        target: Option<String>,
        name: Option<String>,
        #[arg(short, long)]
        namespace: Option<String>,
        #[arg(short, long, value_enum, default_value = "table")]
        output: Output,
        /// After the table, print each row that changes, until interrupted (needs kithd)
        #[arg(short, long)]
        watch: bool,
    },
    /// Delete a resource and its history
    Delete {
        #[command(flatten)]
        target: Target,
    },
    /// List the revisions of a resource
    History {
        #[command(flatten)]
        target: Target,
    },
    /// Re-apply an earlier revision
    Rollback {
        #[command(flatten)]
        target: Target,
        /// Revision to go back to, from `kith history`
        #[arg(long, value_name = "REVISION")]
        to: u64,
    },
    /// Give an exclusive DeviceClaim to a workload: its current holder is stopped and this one started
    Switch {
        /// The DeviceClaim, by name
        claim: String,
        /// `NAME` for a Workload, or `KIND/NAME` (`Job/NAME`)
        workload: String,
        #[arg(short, long)]
        namespace: Option<String>,
    },
    /// Print the output of a Workload's, NodeWorkload's or Job's container or exec unit
    Logs {
        #[command(flatten)]
        target: Target,
        /// Which container or exec unit [default: the first]
        #[arg(short, long, value_name = "NAME")]
        unit: Option<String>,
        /// Which replica, or which run of a Job
        #[arg(long, default_value_t = 0)]
        replica: u32,
        /// Its error output instead
        #[arg(long)]
        stderr: bool,
        /// The output moved aside when the log reached its size cap
        #[arg(long)]
        previous: bool,
        /// Only the last LINES lines
        #[arg(long, value_name = "LINES")]
        tail: Option<u64>,
        /// Keep printing as output arrives, until the unit is done
        #[arg(short, long)]
        follow: bool,
    },
    /// Run one container without a file: a Job whose output and exit code are this command's, or with -d a Workload (`run` is for apps' windows)
    Launch(launch::Launch),
    /// List what runs: each unit of the Workloads, NodeWorkloads and Jobs, with its node, state, exit code and age
    Ps(launch::Ps),
    /// Run an app on a node and show its window here, through waypipe (installed on both ends)
    Run {
        /// The node's name, or labels (KEY=VALUE[,KEY=VALUE]) for the first ready node that has them
        #[arg(long, value_name = "NODE|SELECTOR")]
        on: String,
        /// The program that carries the window [default: waypipe]
        #[arg(long, value_name = "PROGRAM")]
        via: Option<String>,
        /// The app and its arguments, as written after `--`
        #[arg(last = true, required = true, value_name = "APP")]
        argv: Vec<String>,
    },
    /// Print the JSON Schema of a kind, or list the kinds
    Schema { kind: Option<String> },
    /// Manage the nodes of the cluster
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
    /// Remote peers: a phone or a laptop that joins the mesh over WireGuard
    Peer {
        #[command(subcommand)]
        command: PeerCommand,
    },
    /// Contexts: names for a remote kithd and the identity that calls it
    Context {
        #[command(subcommand)]
        command: ContextCommand,
    },
    /// Identities: who may call the API over the network, as their Roles allow
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
    /// The cluster's certificate authority: its public certificate, for a phone or laptop to trust
    Ca {
        #[command(subcommand)]
        command: CaCommand,
    },
    /// The admin's key: what signs the cluster's writes under `spec.signing: required`
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
    /// Show who changed what through this node, and who was refused
    Audit {
        /// How many of the last entries to show (1000 at most)
        #[arg(long, default_value_t = 100)]
        tail: u64,
    },
    /// Open kithd's web UI to a browser on this machine (prints the address)
    Ui {
        /// The loopback port to listen on; any free one when left out
        #[arg(long, default_value_t = 0)]
        port: u16,
    },
    /// Controllers: WebAssembly modules kithd runs for a kind of your own
    Controller {
        #[command(subcommand)]
        command: ControllerCommand,
    },
    /// Blobs: bytes the cluster keeps under their hash, on several nodes
    Blob {
        #[command(subcommand)]
        command: BlobCommand,
    },
    /// A volume's files: copy a directory into it, or what it holds out of it
    Volume {
        #[command(subcommand)]
        command: VolumeCommand,
    },
    /// Backups: put one of a Backup's archives back into its volume
    Backup {
        #[command(subcommand)]
        command: BackupCommand,
    },
    /// Images: what a node holds, checked on request
    Image {
        #[command(subcommand)]
        command: ImageCommand,
    },
    /// Work on a package: a directory of resource templates and default values
    Package {
        #[command(subcommand)]
        command: PackageCommand,
    },
    /// Sources: what a cluster keeps synced from git or a registry
    Source {
        #[command(subcommand)]
        command: SourceCommand,
    },
    /// Dev machines: a Workload that runs as you, its home on a replicated Volume
    Machine {
        #[command(subcommand)]
        command: machine::Machine,
    },
    /// Translate Kubernetes manifests or a Helm chart into kith resources
    Import {
        #[command(subcommand)]
        command: import::Import,
    },
    /// The Docker Engine API on a socket, so the `docker` command works against kith (cargo feature `docker`)
    #[cfg(feature = "docker")]
    Docker {
        #[command(subcommand)]
        command: DockerCommand,
    },
}

#[cfg(feature = "docker")]
#[derive(Subcommand)]
enum DockerCommand {
    /// Listen until interrupted; then `DOCKER_HOST=unix://PATH docker version`
    Serve {
        /// The socket to make, readable by you alone [default: docker.sock beside kithd's socket]
        #[arg(long, value_name = "PATH")]
        listen: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ControllerCommand {
    /// Put WebAssembly modules in a kind's KindDefinition: its controller, its admission hook
    Set {
        /// The kind, as its KindDefinition names it
        kind: String,
        /// The module kithd runs for each resource of the kind (`kith_reconcile`)
        #[arg(long, value_name = "FILE")]
        controller: Option<PathBuf>,
        /// The module kithd asks before a resource of the kind is written (`kith_admit`)
        #[arg(long, value_name = "FILE")]
        admission: Option<PathBuf>,
    },
}

/// Bytes as base64, the way a KindDefinition carries a module.
fn base64(bytes: &[u8]) -> String {
    const LETTERS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut text = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for three in bytes.chunks(3) {
        let bits = three.iter().fold(0u32, |bits, byte| bits << 8 | u32::from(*byte)) << (8 * (3 - three.len()));
        for place in 0..4 {
            let letter = LETTERS[(bits >> (18 - 6 * place) & 63) as usize] as char;
            text.push(if place <= three.len() { letter } else { '=' });
        }
    }
    text
}

#[derive(Subcommand)]
enum AdminCommand {
    /// Set the Cluster's spec.adminKey from a passphrase typed now (kept nowhere): the key
    /// that signs writes under `spec.signing: required`, the same one each time it is typed
    Key,
}

#[derive(Subcommand)]
enum ContextCommand {
    /// Keep NAME as a kithd's address and an identity directory; a second add of a name replaces it
    Add {
        name: String,
        /// The node's --listen address
        #[arg(long, value_name = "HOST:PORT")]
        server: String,
        /// The directory `kith identity cert` wrote: ca.crt, NAME.crt and NAME.key
        #[arg(long, value_name = "DIR")]
        identity: PathBuf,
    },
    /// Make NAME the context kith uses when none is named
    Use { name: String },
    /// List the contexts, the current one starred
    Ls,
    /// Forget NAME
    Rm { name: String },
}

#[derive(Subcommand)]
enum IdentityCommand {
    /// Write a certificate and key for an Identity (made if it is not there) as NAME.crt,
    /// NAME.key and ca.crt; a certificate it had before stops working
    Cert {
        name: String,
        /// The directory to write them in
        #[arg(long, default_value = ".")]
        out: PathBuf,
    },
}

#[derive(Subcommand)]
enum CaCommand {
    /// Write the LAN CA's certificate (public: never a key) to FILE, or print it; run it on the
    /// node that holds the CA. It vouches only for the cluster's LAN names (`spec.lanDomains`), so
    /// trust it once on a device and the hosts that say `expose.issuer: cluster` open there
    /// without a warning, and no other name does
    Export { file: Option<PathBuf> },
}

#[derive(Subcommand)]
enum BlobCommand {
    /// Keep FILE's bytes in the cluster; prints the name they are kept under
    Put {
        file: PathBuf,
        #[arg(short, long, default_value = DEFAULT_NAMESPACE)]
        namespace: String,
        /// On how many nodes [default: 2]
        #[arg(long)]
        copies: Option<u32>,
    },
    /// The bytes kept under NAME, to standard output or into a file
    Get {
        name: String,
        #[arg(short, long, default_value = DEFAULT_NAMESPACE)]
        namespace: String,
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum VolumeCommand {
    /// Copy what is in the directory PATH (or the file PATH) into the Volume NAME, beside
    /// what is there; with - as PATH, a tar from standard input
    Put {
        name: String,
        path: PathBuf,
        #[arg(short, long, default_value = DEFAULT_NAMESPACE)]
        namespace: String,
    },
    /// Copy what is in the Volume NAME into the directory PATH; with - as PATH, as a tar
    /// to standard output
    Get {
        name: String,
        path: PathBuf,
        #[arg(short, long, default_value = DEFAULT_NAMESPACE)]
        namespace: String,
    },
}

#[derive(Subcommand)]
enum BackupCommand {
    /// Unpack a backup of the Backup NAME into its volume, which must be empty
    Restore {
        name: String,
        #[arg(short, long, default_value = DEFAULT_NAMESPACE)]
        namespace: String,
        /// Which one: the `at` of one in the Backup's status [default: the last]
        #[arg(long, value_name = "SECONDS")]
        at: Option<u64>,
    },
}

#[derive(Subcommand)]
enum ImageCommand {
    /// Check the packages of an image NODE has against OSV (osv.dev), and print the advisories
    /// that name them. Only an image the node already has is looked at (nothing is pulled), and what
    /// OSV is sent is the release's ecosystem and each package's name and version: see the
    /// workloads guide, "Is an image known to be vulnerable"
    Scan {
        /// The image, as a unit names it (`docker.io/library/debian:12`)
        image: String,
        /// The node that has it
        #[arg(long)]
        node: String,
    },
}

#[derive(Subcommand)]
enum SourceCommand {
    /// Let a Source with `approval: manual` apply the revision that waits in its status
    Approve {
        name: String,
        #[arg(short, long)]
        namespace: Option<String>,
    },
    /// Put a directory's YAML and JSON files in a registry, for a Source to sync (`oci:`)
    Push {
        dir: PathBuf,
        /// Where: `oci://HOST/PATH/NAME[:TAG]`
        #[arg(long, value_name = "URL")]
        to: String,
    },
}

#[derive(Subcommand)]
enum PackageCommand {
    /// Print the resources a package renders to (and its notes, on stderr); nothing is applied
    Render {
        /// The package's directory
        dir: PathBuf,
        /// The release's name: what the resources are named for [default: the package's name]
        #[arg(long)]
        name: Option<String>,
        /// The namespace of resources that name none
        #[arg(short, long, default_value = "default")]
        namespace: String,
        /// A YAML file of values over the package's defaults; later ones win
        #[arg(short = 'f', long = "values", value_name = "FILE")]
        values: Vec<PathBuf>,
        /// One value over those: `replicas=3`, `expose.host=example.org`. Read as YAML,
        /// so quote text that looks like a number: `'tag="1.10"'`
        #[arg(long = "set", value_name = "KEY=VALUE")]
        set: Vec<String>,
    },
    /// Check a package: its files, its schema, and what it renders to with its default values
    Lint {
        /// The package's directory
        dir: PathBuf,
    },
    /// Put a package in the cluster, as the Package `NAME-VERSION`, for Releases to
    /// install; or, with --to, in a registry
    Push {
        /// The package's directory
        dir: PathBuf,
        /// The repository to put it in instead: `oci://HOST/PATH`
        #[arg(long, value_name = "URL")]
        to: Option<String>,
        /// Sign it with this key (from `kith package keygen`)
        #[arg(long, value_name = "FILE", requires = "to")]
        key: Option<PathBuf>,
    },
    /// Fetch a package from a registry into a directory
    Pull {
        /// The repository: `oci://HOST/PATH`
        from: String,
        name: String,
        version: String,
        /// The public key it must be signed with [default: taken unsigned or signed by anyone]
        #[arg(long, value_name = "HEX")]
        public_key: Option<String>,
        /// Where to put it [default: NAME-VERSION]
        #[arg(short, long, value_name = "DIR")]
        output: Option<PathBuf>,
    },
    /// Make a key to sign packages with: the secret into FILE, the public key printed
    Keygen { file: PathBuf },
}

/// `a.b=1` as values: `{a: {b: 1}}`. The value is read as YAML, and is text if it is none.
fn set_value(assignment: &str) -> Result<serde_json::Value, String> {
    let Some((path, value)) = assignment.split_once('=') else {
        return fail(format!("--set {assignment}: write KEY=VALUE"));
    };
    let value = kith_yaml::from_str(value).unwrap_or_else(|_| serde_json::Value::String(value.into()));
    let nest = |inside, key: &str| serde_json::json!({ key: inside });
    Ok(path.rsplit('.').fold(value, nest))
}

#[derive(Subcommand)]
enum PeerCommand {
    /// Make a key for a new peer, let it in at a level, and print its WireGuard configuration, once
    Add {
        /// The peer's name
        name: String,
        /// The node (started with --people and --people-endpoint) it connects to
        #[arg(long)]
        node: String,
        /// The AccessLevel it gets: what it may reach
        #[arg(long)]
        level: String,
        /// The name already has a key: give it a new one, which ends the old (its phone stops)
        #[arg(long)]
        replace: bool,
    },
}

/// What `kith peer add` prints from kithd's answer: the configuration, which holds the peer's
/// private key, with the word that it is shown this once.
fn peer_text(answer: &serde_json::Value) -> Result<String, String> {
    let Some(config) = answer["config"].as_str().filter(|config| !config.is_empty()) else {
        return fail("kithd's answer holds no configuration: update kithd");
    };
    let name = answer["name"].as_str().unwrap_or("the peer");
    let node = answer["node"].as_str().unwrap_or("its node");
    Ok(format!(
        "{name}'s WireGuard configuration for {node}, shown this once and kept nowhere: put it in the WireGuard app (scan the QR code of the web UI's Add a peer instead, or paste this) before you lose it. It holds {name}'s private key: whoever has it is this peer. Take the peer away with `kith delete RemotePeer {name}`.\n\n{config}"
    ))
}

#[derive(Subcommand)]
enum NodeCommand {
    /// Print a token that lets one more node join, within the hour: `kithd --join ADDR:PORT --token TOKEN`
    Token {
        /// The node it lets in is a worker (`spec.trust: worker`): it never votes on the
        /// store, and nothing that asks for control nodes is placed on it
        #[arg(long)]
        worker: bool,
        /// That worker serves ingress (`kithd --ingress`): besides what is placed on it, it is
        /// sent the certificate (and key) of every exposed host and the ACME account's
        /// thumbprint, never the account key; a control node with `--acme` orders its certificates
        #[arg(long, requires = "worker")]
        ingress: bool,
    },
    /// Say which node leads the store, which nodes vote, and how far this one has got
    Status,
    /// Print the `--spec` file of the features NAME's hardware wants, from its PCI cards:
    /// `kith node features NAME > NAME.yaml`, then `sh os/build.sh --spec NAME.yaml --out DIR`
    Features {
        /// The node, as `kith get Node` names it
        name: String,
    },
    /// Move what runs on NAME to other nodes, and keep new replicas off it: each replica that
    /// cannot move is said first. A running Job and a replica pinned to NAME stay where they are
    Drain {
        name: String,
        /// Say what would happen, and change nothing
        #[arg(long)]
        dry_run: bool,
    },
    /// Let NAME take replicas again: takes off what `kith node drain` put on it
    Undrain { name: String },
    /// Have this node install machines that start from the network (PXE): each erases its disk and joins
    ///
    /// For an hour at most, and only the machines whose network cards are named. Without
    /// arguments: whether it is on, and which machines have fetched the installer.
    Netboot {
        /// The network boot file (os/build.sh writes target/os/kith-netboot.efi): turns it on
        #[arg(long, value_name = "FILE", requires = "mac")]
        image: Option<PathBuf>,
        /// A machine to install, by its network card's address (52:54:00:12:34:56); may repeat
        #[arg(long, value_name = "ADDRESS", requires = "image")]
        mac: Vec<String>,
        /// Turn it off after this many minutes
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=60))]
        minutes: u64,
        /// The disk each machine installs on: a name, or `only` for machines with one disk
        #[arg(long, default_value = "only", value_name = "NAME")]
        disk: String,
        /// The machines keep their state encrypted, its key held by the cluster (`kith node lock`)
        #[arg(long, requires = "image")]
        encrypt: bool,
        /// Turn it off now
        #[arg(long, conflicts_with = "image")]
        off: bool,
    },
    /// Have the cluster stop handing out the key of NAME's encrypted state: it restarts, and waits
    Lock { name: String },
    /// Hand the key of NAME's encrypted state out again
    Unlock { name: String },
    /// Let NAME's own TPM keep the key of its encrypted state, sealed to the system it runs: it then
    /// starts with no node asked (a laptop away from home), and so does whoever takes it whole
    Seal {
        name: String,
        /// Take that back: the node drops its seal when it hears of it
        #[arg(long)]
        off: bool,
    },
    /// Give NAME a passphrase that opens its encrypted state where no node is in reach, typed at its
    /// console when it starts (a laptop away from home): its key then lies on its disk, behind the passphrase
    Passphrase {
        name: String,
        /// Take it away: the node asks the cluster again, and nothing else
        #[arg(long)]
        off: bool,
    },
    /// Have NAME's state open with its TPM and a PIN, typed at its console when it starts: its TPM
    /// alone opens it no more, and the TPM refuses every PIN for a while after a few wrong ones
    Pin {
        name: String,
        /// Say that this machine's TPM has not been tried as docs/adr-unlock.md's "On hardware: the
        /// owner's checklist" says: no PIN is set without it, as none has yet run on a real TPM. It is
        /// the owner's word, not a lock: whoever may apply a NodeKey at NAME can send it. With it,
        /// kithd takes the TPM's lockout authorization where it is empty and keeps it only in NAME's
        /// encrypted state: if that state is lost, only clearing the TPM gives it back. Each setting
        /// tries one wrong PIN, which the TPM counts. Use random digits (a date is among the first
        /// guesses)
        #[arg(long, conflicts_with = "off")]
        untried_tpm: bool,
        /// Take it away: the node asks the cluster again (its TPM alone opens it only if sealed)
        #[arg(long)]
        off: bool,
    },
    /// Forget the key of NAME's encrypted state for good: what its disk holds can no longer be read
    Wipe {
        name: String,
        /// The node's name once more: there is no way back
        #[arg(long, value_name = "NAME")]
        erase: String,
    },
    /// Have NAME, running, make a new recovery key for its encrypted state and show it, once: the
    /// one it had opens it no more (an install nobody watched printed a key nobody saw)
    Recovery { name: String },
    /// Encrypt NAME's state in place, with no reinstall: NAME, drained, makes the key and the
    /// recovery key as the installer does, shows the recovery key once, and restarts to encrypt the
    /// state as it starts. `--cancel` takes away an encryption that has not started
    Encrypt {
        name: String,
        /// Take the encryption away, if it has not started, instead of starting it
        #[arg(long)]
        cancel: bool,
    },
    /// A second disk for NAME's data: add one, take one away, or list what it holds (docs/adr-second-disk.md)
    Disk {
        #[command(subcommand)]
        command: DiskCommand,
    },
    /// Make a duress code for NAME and show it, once: typed at NAME's waiting console in place of
    /// the recovery key, it erases what that disk opens with and has the cluster forget its key,
    /// and the console answers as it does a wrong key. There is no way back
    Duress {
        #[arg(required_unless_present = "all", conflicts_with = "all")]
        name: Option<String>,
        /// One code for the whole cluster: typed at any encrypted node's waiting console, it erases
        /// that node as above and has the cluster forget the key of every other, which then opens
        /// with its own recovery key alone (so each must have one somebody was shown)
        #[arg(long)]
        all: bool,
        /// Take the code away: it does nothing from when the node hears of it
        #[arg(long)]
        off: bool,
    },
}

#[derive(Subcommand)]
enum DiskCommand {
    /// Make the disk of this serial NODE's data disk: it is overwritten, so what is on it is gone, and
    /// its key is kept in NODE's encrypted state (a node whose state is not encrypted adds none). Run
    /// where kithd runs (kithd's own socket): NODE is the node that kithd is
    Add {
        node: String,
        /// The disk's serial, as `kith node disk list` or the installer shows it; nothing else names a disk
        #[arg(long)]
        serial: String,
        /// Overwrite a disk that holds a partition table, a filesystem or any data. Never the disk the
        /// system runs from, a stick or a card reader
        #[arg(long)]
        wipe: bool,
        /// Discard the disk's blocks instead of writing zeros through the encryption: fast on a large
        /// virtual or flash disk, and not a wipe of what a disk without discard held before
        #[arg(long)]
        quick: bool,
    },
    /// Take a data disk away from NODE: its header is zeroed, its key forgotten here, and what it holds
    /// can no more be read (the disk is not erased)
    Remove {
        node: String,
        /// The disk's id, as `kith node disk list` shows it (32 hex digits)
        id: String,
    },
    /// List the disks NODE has, mounted or not, and the ones it left alone
    List { node: String },
}

/// What `kith image scan` says of the answer: how many packages were looked at, and a row for each
/// advisory id of each package OSV has any for, with the id's osv.dev link. (Package names and ids
/// come out of an image: what is not printable is a `?`, whatever a node sent.)
fn scan_said(said: &serde_json::Value) -> String {
    let text = |value: &serde_json::Value| -> String {
        value
            .as_str()
            .unwrap_or("?")
            .chars()
            .map(|c| if c.is_control() { '?' } else { c })
            .collect()
    };
    let hits = said["vulnerable"].as_array().cloned().unwrap_or_default();
    let mut out = format!(
        "{} on {}: {} packages ({}), {} with advisories in OSV\n",
        text(&said["image"]),
        text(&said["node"]),
        said["packages"].as_u64().unwrap_or(0),
        text(&said["ecosystem"]),
        hits.len()
    );
    let mut rows = vec![];
    for hit in &hits {
        let ids = hit["ids"].as_array().cloned().unwrap_or_default();
        for (n, id) in ids.iter().enumerate() {
            let (name, version) = if n == 0 {
                (text(&hit["name"]), text(&hit["version"]))
            } else {
                (String::new(), String::new())
            };
            let id = text(id);
            rows.push((name, version, format!("{id}  https://osv.dev/vulnerability/{id}")));
        }
    }
    if rows.is_empty() {
        return out;
    }
    rows.insert(0, ("PACKAGE".into(), "VERSION".into(), "ADVISORY".into()));
    let width = |pick: fn(&(String, String, String)) -> &String| {
        rows.iter().map(|r| pick(r).chars().count()).max().unwrap_or(0)
    };
    let (a, b) = (width(|r| &r.0), width(|r| &r.1));
    for (name, version, id) in &rows {
        out.push_str(format!("{name:a$}  {version:b$}  {id}").trim_end());
        out.push('\n');
    }
    out
}

/// What `kith node disk list` says of the answer's `known` and `unknown`.
fn disks_said(said: &serde_json::Value) -> String {
    let text = |one: &serde_json::Value, key: &str| one[key].as_str().unwrap_or("").to_string();
    let mut out = String::new();
    for (title, none, key) in [
        ("data disks:", "no data disks", "known"),
        ("left alone:", "no other disks", "unknown"),
    ] {
        let all = said[key].as_array().cloned().unwrap_or_default();
        if all.is_empty() {
            out.push_str(&format!("{none}\n"));
            continue;
        }
        out.push_str(&format!("{title}\n"));
        for one in all {
            let who = match (one["disk"].as_str(), one["serial"].as_str()) {
                (Some(disk), _) => disk.to_string(),
                (None, serial) => format!("serial {}", serial.unwrap_or("?")),
            };
            let id = one["id"].as_str().map(|id| format!("  id {id}")).unwrap_or_default();
            let why = one["why"].as_str().map(|why| format!(": {why}")).unwrap_or_default();
            out.push_str(&format!("  {who}  {}{why}{id}\n", text(&one, "state")));
        }
    }
    out
}

#[derive(Args)]
struct Files {
    /// YAML, JSON or `.kith` file, a directory of them, or `-` for stdin
    #[arg(short, long = "file", value_name = "PATH", required = true)]
    files: Vec<PathBuf>,
}

#[derive(Args)]
struct Target {
    /// KIND/NAME, or KIND followed by NAME
    target: String,
    name: Option<String>,
    #[arg(short, long)]
    namespace: Option<String>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Output {
    Table,
    Yaml,
    Json,
}

/// `println!` panics when stdout is closed (`kith get | head`); stop quietly instead.
macro_rules! println {
    ($($arg:tt)*) => {{
        use std::io::Write;
        if writeln!(std::io::stdout(), $($arg)*).is_err() {
            std::process::exit(0);
        }
    }};
}

fn main() -> ExitCode {
    // First, before the arguments are read: what musl's start code left writable is shut.
    if let Err(e) = kith_dm_sys::seal_relro() {
        // (Not `eprintln!`: it panics when stderr cannot be written.)
        let _ = std::io::Write::write_fmt(
            &mut std::io::stderr(),
            format_args!("kith: could not make its tables of functions read-only: {e}\n"),
        );
    }
    let code = match run(Cli::parse()) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("{msg}");
            ExitCode::from(2)
        }
    };
    // For ci/budgets.py: a parent can't measure this from outside, because the
    // rusage it gets back includes its own pre-exec memory.
    if std::env::var_os("KITH_PRINT_PEAK_RSS").is_some() {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        if let Some(line) = status.lines().find(|l| l.starts_with("VmHWM:")) {
            eprintln!("{line}");
        }
    }
    code
}

fn fail<T>(e: impl std::fmt::Display) -> Result<T, String> {
    Err(format!("error: {e}"))
}

/// Load the package in `dir`; say, and go on, when its `kithVersion` is not this kith's
/// (the cluster's kithd is what refuses to install it, T-0990).
fn load_package(dir: &Path) -> Result<kith_packages::Package, String> {
    let package = kith_packages::Package::load(dir).or_else(fail)?;
    if let Some(why) = package.meta.kith_mismatch(env!("CARGO_PKG_VERSION")) {
        eprintln!("warning: {why}");
    }
    Ok(package)
}

/// Where the resources live: kithd behind its socket, or a store file used directly.
enum Backend {
    Daemon(Kithd),
    Local(PathBuf),
}

impl Backend {
    /// Local changes go through here: nothing is saved unless `change` succeeds.
    fn local<T>(
        path: &Path,
        write: bool,
        change: impl FnOnce(&mut Store) -> Result<T, store::Error>,
    ) -> Result<T, String> {
        // Commands that only look never create, lock or wait for the store.
        let mut file_store = if write {
            FileStore::open(path)
        } else {
            FileStore::read(path)
        }
        .or_else(fail)?;
        let value = change(&mut file_store.store).or_else(fail)?;
        if write {
            file_store.save().or_else(fail)?;
        }
        Ok(value)
    }

    /// All or nothing. A dry run reports the same changes and keeps none of them.
    fn apply(&self, resources: Vec<Resource>, dry_run: bool) -> Result<Vec<Change>, String> {
        // (Refused here as kithd refuses it, so a local store takes no dotted name either.)
        resources.iter().try_for_each(Resource::submitted)?;
        match self {
            Backend::Local(path) => Self::local(path, !dry_run, |store| store.apply_all(resources)),
            Backend::Daemon(socket) => {
                let body = serde_json::to_vec(&resources).or_else(fail)?;
                let query = if dry_run { "?dryRun=true" } else { "" };
                request(socket, "POST", &format!("/v1/apply{query}"), &body)
            }
        }
    }

    /// Have kithd do something with a registry: `kith` itself speaks to none.
    fn registry<T: serde::de::DeserializeOwned>(&self, verb: &str, asked: &serde_json::Value) -> Result<T, String> {
        match self {
            Backend::Local(_) => fail("a registry is reached through kithd: not with --store"),
            Backend::Daemon(socket) => request(
                socket,
                "POST",
                &format!("/v1/packages/{verb}"),
                asked.to_string().as_bytes(),
            ),
        }
    }

    fn list(&self, kind: Option<&str>) -> Result<Vec<Resource>, String> {
        match self {
            Backend::Local(path) => Self::local(path, false, |store| Ok(store.list(kind).cloned().collect())),
            Backend::Daemon(socket) => {
                let query = kind.map(|k| format!("?kind={k}")).unwrap_or_default();
                request(socket, "GET", &format!("/v1/resources{query}"), b"")
            }
        }
    }

    fn get(&self, key: &str) -> Result<Resource, String> {
        match self {
            Backend::Local(path) => {
                let found = |store: &mut Store| store.get(key).cloned().ok_or(store::Error::NotFound(key.into()));
                Self::local(path, false, found)
            }
            Backend::Daemon(socket) => request(socket, "GET", &format!("/v1/resources/{}", escape(key)), b""),
        }
    }

    fn delete(&self, key: &str) -> Result<Resource, String> {
        match self {
            Backend::Local(path) => Self::local(path, true, |store| store.delete(key)),
            Backend::Daemon(socket) => request(socket, "DELETE", &format!("/v1/resources/{}", escape(key)), b""),
        }
    }

    fn history(&self, key: &str) -> Result<Vec<Revision>, String> {
        match self {
            Backend::Local(path) => Self::local(path, false, |store| store.history(key).map(<[Revision]>::to_vec)),
            Backend::Daemon(socket) => request(socket, "GET", &format!("/v1/history/{}", escape(key)), b""),
        }
    }

    fn rollback(&self, key: &str, to: u64) -> Result<Change, String> {
        match self {
            Backend::Local(path) => Self::local(path, true, |store| store.rollback(key, to)),
            Backend::Daemon(socket) => request(socket, "POST", &format!("/v1/rollback/{}?to={to}", escape(key)), b""),
        }
    }
}

struct Kithd {
    route: Route,
    /// How long it may stay silent.
    timeout: std::time::Duration,
}

/// Percent-encode a resource key for a URL path. Valid keys pass through unchanged.
fn escape(key: &str) -> String {
    let plain = |b: u8| b.is_ascii_alphanumeric() || b"-._/".contains(&b);
    key.bytes()
        .map(|b| {
            if plain(b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

/// What is typed at the terminal after `prompt`, unseen (and, when `twice`, again to be the
/// same); from a pipe, its first line.
fn secret(prompt: &str, twice: bool) -> Result<String, String> {
    use nix::sys::termios::{LocalFlags, SetArg, tcgetattr, tcsetattr};
    use std::io::IsTerminal;
    let stdin = std::io::stdin();
    let line = || {
        let mut line = String::new();
        let read = stdin.read_line(&mut line).or_else(|e| fail(format!("stdin: {e}")));
        read.map(|_| line.trim().to_string())
    };
    let shown = stdin.is_terminal().then(|| tcgetattr(&stdin).ok()).flatten();
    let Some(shown) = shown else {
        return line();
    };
    // ponytail: an interrupt while it is typed leaves the terminal unseen (`stty echo`
    // brings it back); a signal handler, if anyone trips on it.
    let mut unseen = shown.clone();
    unseen.local_flags.remove(LocalFlags::ECHO);
    let typed = |prompt: &str| {
        eprint!("{prompt}");
        let _ = tcsetattr(&stdin, SetArg::TCSANOW, &unseen);
        let typed = line();
        let _ = tcsetattr(&stdin, SetArg::TCSANOW, &shown);
        eprintln!();
        typed
    };
    let first = typed(prompt)?;
    if !twice {
        return Ok(first);
    }
    let again = typed("Once more: ")?;
    if first != again {
        return fail("the two are not the same: nothing was done");
    }
    Ok(first)
}

/// Where the admin's passphrase comes from: the terminal, else one line of stdin, which no
/// line can give when stdin carries the input (`apply -f -`): then the manifest goes as a file.
#[derive(Debug, PartialEq)]
enum Source {
    Tty,
    Stdin,
    Refuse,
}

fn passphrase_source(tty_opens: bool, stdin_is_input: bool) -> Source {
    match (tty_opens, stdin_is_input) {
        (true, _) => Source::Tty,
        (false, false) => Source::Stdin,
        (false, true) => Source::Refuse,
    }
}

/// Set once a command reads its input from stdin (`apply -f -`, `volume put -`).
static STDIN_WAS_INPUT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The admin's passphrase: typed at /dev/tty with echo off (twice, when `twice`), else one line
/// of stdin.
fn admin_passphrase(prompt: &str, twice: bool) -> Result<String, String> {
    use std::sync::atomic::Ordering;
    let tty = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty");
    let source = passphrase_source(tty.is_ok(), STDIN_WAS_INPUT.load(Ordering::SeqCst));
    match source {
        Source::Tty => typed_on(&tty.expect("chosen only when /dev/tty opened"), prompt, twice),
        Source::Stdin => one_line(&mut std::io::stdin().lock()),
        Source::Refuse => fail(
            "the admin's passphrase is typed at a terminal, and stdin holds the manifest: give the manifest as a file (kith apply -f FILE)",
        ),
    }
}

/// What is typed on `tty` after `prompt`, unseen (and, when `twice`, again to be the same).
fn typed_on(tty: &std::fs::File, prompt: &str, twice: bool) -> Result<String, String> {
    use nix::sys::termios::{LocalFlags, SetArg, tcgetattr, tcsetattr};
    use std::io::{BufReader, Write};
    let shown = tcgetattr(tty).or_else(|e| fail(format!("/dev/tty: {e}")))?;
    let mut unseen = shown.clone();
    unseen.local_flags.remove(LocalFlags::ECHO);
    let mut out = tty;
    let mut input = BufReader::new(tty);
    let mut typed = |prompt: &str| {
        let _ = out.write_all(prompt.as_bytes()).and_then(|()| out.flush());
        let _ = tcsetattr(tty, SetArg::TCSANOW, &unseen);
        let typed = one_line(&mut input);
        let _ = tcsetattr(tty, SetArg::TCSANOW, &shown);
        let _ = out.write_all(b"\n");
        typed
    };
    let first = typed(prompt)?;
    if !twice {
        return Ok(first);
    }
    let again = typed("Once more: ")?;
    if first != again {
        return fail("the two are not the same: nothing was done");
    }
    Ok(first)
}

/// The next line of `input`, without its line end.
fn one_line(input: &mut impl std::io::BufRead) -> Result<String, String> {
    let mut line = String::new();
    input
        .read_line(&mut line)
        .or_else(|e| fail(format!("reading the passphrase: {e}")))?;
    Ok(line.trim().to_string())
}

/// kithd, open: its socket, or a node over TLS.
fn connect(kithd: &Kithd) -> Result<Wire, String> {
    // A kithd that accepts and then says nothing must not hang a script forever.
    Wire::connect(&kithd.route, Some(kithd.timeout)).map_err(|e| {
        let name = kithd.route.name();
        format!("error: cannot reach kithd at {name}: {e}\nStart kithd, or work on a store file with --store FILE.")
    })
}

/// What a reply that is not a yes says: API errors are `{"error": "..."}`; anything else
/// (a malformed request) is plain text.
fn refusal(body: &[u8]) -> String {
    let message = serde_json::from_slice::<serde_json::Value>(body).ok();
    let message = message.as_ref().and_then(|m| m["error"].as_str()).map(String::from);
    message.unwrap_or_else(|| String::from_utf8_lossy(body).into_owned())
}

/// A chunked body from `from` into `to`: an error if it ends before it says it has.
fn unchunk(from: &mut impl std::io::BufRead, to: &mut dyn std::io::Write) -> std::io::Result<()> {
    loop {
        let mut line = String::new();
        from.read_line(&mut line)?;
        let size = line.trim().split(';').next().unwrap_or_default();
        let size = u64::from_str_radix(size, 16).map_err(|_| std::io::ErrorKind::UnexpectedEof)?;
        if size == 0 {
            return Ok(());
        }
        if std::io::copy(&mut (&mut *from).take(size), to)? != size {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        from.read_line(&mut line)?;
    }
}

/// One request to kithd whose body (`from`, sent in chunks as it is read) or whose reply
/// (written to `to` as it comes) is too long to hold: a volume's files. The reply's body,
/// when it did not go to `to`. An error reading `from` ends the request unfinished, which
/// kithd takes as no request at all.
/// Why a body sent as a stream (a volume's files put from stdin or a tar) cannot be sent to a
/// cluster that says `signing: required`: the digest the signature covers is not known until the
/// body is all sent, so it goes unsigned, and kithd refuses an unsigned change there. Stays so.
fn streamed_refusal(status: &serde_json::Value) -> Option<&'static str> {
    (status["signing"] == "required").then_some(
        "this cluster requires the admin's signature (spec.signing: required), and a volume's files \
         sent as a stream cannot be signed yet, so the put is refused: nothing was sent",
    )
}

fn carry(
    kithd: &Kithd,
    method: &str,
    path: &str,
    from: Option<&mut dyn Read>,
    to: Option<&mut dyn std::io::Write>,
) -> Result<Vec<u8>, String> {
    use std::io::{BufRead, Write};
    // (A body sent in chunks is not signed: its digest is not known before it is sent. Where the
    // cluster requires the admin's signature kithd refuses it unsigned, so it is refused here, and
    // says why, before any of it is sent. That stays so until a streamed body can be signed.)
    if from.is_some() && matches!(kithd.route, Route::Socket(_)) {
        let status: serde_json::Value = request(kithd, "GET", "/v1/cluster", b"")?;
        if let Some(why) = streamed_refusal(&status) {
            return fail(why);
        }
    }
    let asked = if from.is_none() {
        signed(kithd, method, path, b"")?
    } else {
        None
    };
    let signed = match asked {
        Some(header) => format!("{}: {header}\r\n", signing::SIGNED),
        None => String::new(),
    };
    let mut stream = connect(kithd)?;
    let framing = if from.is_some() {
        "Transfer-Encoding: chunked\r\n"
    } else {
        ""
    };
    let head = format!("{method} {path} HTTP/1.1\r\nHost: kithd\r\nConnection: close\r\n{framing}{signed}\r\n");
    let mut sent = stream.write_all(head.as_bytes());
    if let Some(from) = from {
        let mut chunk = vec![0; 64 << 10];
        // (Until the chunk of no bytes, which says that was all. kithd may refuse before
        // it has read everything: its reply still says why.)
        while sent.is_ok() {
            let n = from
                .read(&mut chunk)
                .or_else(|e| fail(format!("reading what to send: {e}")))?;
            sent = write!(stream, "{n:x}\r\n").and_then(|()| stream.write_all(&chunk[..n]));
            sent = sent.and_then(|()| stream.write_all(b"\r\n"));
            if n == 0 {
                break;
            }
        }
    }
    let mut reply = std::io::BufReader::new(stream);
    let mut head = String::new();
    loop {
        let mut line = String::new();
        if reply.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
            break;
        }
        head.push_str(&line.to_ascii_lowercase());
    }
    if head.is_empty() {
        let why = sent
            .err()
            .map_or("kithd sent no reply".to_string(), |e| format!("talking to kithd: {e}"));
        return fail(why);
    }
    let ok = head.split(' ').nth(1).is_some_and(|status| status.starts_with('2'));
    let length = head.lines().find_map(|line| line.strip_prefix("content-length:"));
    let length = length.and_then(|length| length.trim().parse::<u64>().ok());
    let mut body = Vec::new();
    let out: &mut dyn Write = match to {
        Some(to) if ok => to,
        _ => &mut body,
    };
    let read = match length {
        _ if head.contains("transfer-encoding: chunked") => unchunk(&mut reply, out),
        Some(length) => std::io::copy(&mut (&mut reply).take(length), out).and_then(|read| {
            let all = read == length;
            all.then_some(()).ok_or(std::io::ErrorKind::UnexpectedEof.into())
        }),
        None => std::io::copy(&mut reply, out).map(drop),
    };
    match read {
        _ if !ok => fail(refusal(&body)),
        Err(e) => fail(format!("kithd's reply was cut short: {e}")),
        Ok(()) => Ok(body),
    }
}

/// The machine's own tar, at work in `dir` on a tar it reads or writes as `mode` says.
// ponytail: kith has no tar of its own (its size); a machine with none gives - as PATH
// and pipes one.
fn tar(mode: &str, dir: &Path) -> std::process::Command {
    let mut tar = std::process::Command::new("tar");
    tar.arg(mode).arg("-").arg("-C").arg(dir);
    tar
}

/// What a program writes, which ends in an error if the program does.
struct Piped(std::process::Child, std::process::ChildStdout);

impl Read for Piped {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.1.read(buf)?;
        if n == 0 && !self.0.wait()?.success() {
            return Err(std::io::Error::other("tar did not read all of it (it says why above)"));
        }
        Ok(n)
    }
}

/// What `kith node drain` says before it changes anything: one line per copy kithd's plan
/// (`GET /v1/drain/NAME`) puts on the node, and what happens to it.
fn drain_text(name: &str, plan: &[serde_json::Value]) -> Vec<String> {
    if plan.is_empty() {
        return vec![format!("nothing runs on {name}: nothing moves")];
    }
    plan.iter()
        .map(|line| {
            let key = line["key"].as_str().unwrap_or_default();
            let who = match line["replica"].as_str() {
                Some(replica) => format!("{key}#{replica}"),
                None => key.to_string(),
            };
            let why = line["why"].as_str().unwrap_or_default();
            let if_lost = line["if_lost"].as_str().unwrap_or_default();
            match line["outcome"].as_str().unwrap_or_default() {
                "moves" => format!("  {who} moves to {}", line["to"].as_str().unwrap_or_default()),
                "stays" => format!("  {who} stays on {name}: {why}; if {name} is lost, {if_lost}"),
                "removed" => format!("  {who} comes off {name}: {why}; {if_lost}"),
                "unplaced" => format!("  {who} cannot be placed on any node: {why}"),
                // A word a newer kithd says: shown as it is, not as one of the above.
                other => format!("  {who}: {other}: {why}"),
            }
        })
        .collect()
}

/// One HTTP request to kithd over its unix socket.
// ponytail: HTTP/1.1 by hand keeps an HTTP client and an async runtime out of the CLI
// (the size and RSS budgets). It relies on `Connection: close` and kithd never
// chunking these replies; swap in a client library when the API goes over the network.
fn request<T: serde::de::DeserializeOwned>(kithd: &Kithd, method: &str, path: &str, body: &[u8]) -> Result<T, String> {
    let reply = raw(kithd, method, path, body)?;
    serde_json::from_slice(&reply).or_else(|e| fail(format!("reading kithd's reply: {e}")))
}

/// The passphrase typed for this run's signed writes: asked for once, when the first is signed.
static PASSPHRASE: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// Set by a long-running verb (`docker serve`) once it serves: a request thread never prompts.
static NO_PROMPT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// For a verb that serves: where kithd needs the admin's signature, ask for the passphrase now,
/// once, before the first request (never in a request thread), and derive the key. A passphrase
/// that comes out empty (no terminal, nothing on stdin) is refused here with a clear message.
#[cfg(feature = "docker")]
fn sign_before_serving(backend: &Backend) -> Result<(), String> {
    if let Backend::Daemon(kithd) = backend {
        // (A kithd that is not up yet is no reason not to serve: its calls fail as they come.)
        match request::<serde_json::Value>(kithd, "GET", "/v1/cluster", b"") {
            Err(e) => eprintln!("kith: kithd does not answer yet ({e}): serving; calls fail until it does"),
            Ok(_) => {
                signed(kithd, "POST", "/v1/apply", b"")?;
                if PASSPHRASE.get().is_some_and(String::is_empty) {
                    return fail(
                        "this cluster requires the admin's signature (spec.signing: required): give the passphrase at a terminal or as one line on stdin, as kith docker serve asks for it once, before it serves",
                    );
                }
            }
        }
    }
    NO_PROMPT.store(true, std::sync::atomic::Ordering::SeqCst);
    Ok(())
}

/// The admin's key from it, for the cluster kithd named: one cluster per run.
static KEY: std::sync::OnceLock<ring::signature::Ed25519KeyPair> = std::sync::OnceLock::new();

/// The signature a request to kithd's socket carries where the cluster says `signing: required`
/// (none for a node over TLS, an open cluster, or a read of the node's own: kithd reads those as
/// its own). A read another node may pass on is signed: the logs and a volume's files (kithd's
/// and this crate's `passed_on`, kith-api). Its key is the passphrase's, salted with the cluster id kithd gives.
fn signed(kithd: &Kithd, method: &str, path: &str, body: &[u8]) -> Result<Option<String>, String> {
    if (matches!(method, "GET" | "HEAD") && !kith_api::passed_on(method, path))
        || !matches!(kithd.route, Route::Socket(_))
    {
        return Ok(None);
    }
    let status: serde_json::Value = request(kithd, "GET", "/v1/cluster", b"")?;
    if status["signing"] != "required" {
        return Ok(None);
    }
    let Some(cluster) = status["clusterId"].as_str() else {
        return fail("kithd gave no cluster id to sign with: update kithd");
    };
    // (The key is derived once per run: PBKDF2 at 600000 rounds is the slow part, and a follow polls.)
    let key = match KEY.get() {
        Some(key) => key,
        None => {
            if PASSPHRASE.get().is_none() {
                if NO_PROMPT.load(std::sync::atomic::Ordering::SeqCst) {
                    return fail(
                        "this cluster began requiring the admin's signature after kith docker serve started: restart it",
                    );
                }
                let typed = admin_passphrase("The admin's passphrase, which signs this change: ", false)?;
                let _ = PASSPHRASE.set(typed);
            }
            KEY.get_or_init(|| signing::key(PASSPHRASE.get().map_or("", String::as_str), cluster))
        }
    };
    let asked = signing::Request { method, path, body };
    // "*": this node is the one it is sent to, and a node passes it on only to where it belongs.
    let header = signing::header(
        key,
        cluster,
        "*",
        &asked,
        kith_api::store::now() + 300,
        &signing::nonce()?,
    );
    Ok(Some(header))
}

/// The same, the reply's body as it came.
fn raw(kithd: &Kithd, method: &str, path: &str, body: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::Write;
    // (Before the connection: a signed write first asks kithd for its cluster's id.)
    let signed = match signed(kithd, method, path, body)? {
        Some(header) => format!("{}: {header}\r\n", signing::SIGNED),
        None => String::new(),
    };
    let mut stream = connect(kithd)?;
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: kithd\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{signed}\r\n",
        body.len()
    );
    let mut reply = Vec::new();
    let sent = stream.write_all(head.as_bytes()).and_then(|()| stream.write_all(body));
    // kithd may refuse a request before reading all of it (too large): its reply still explains why.
    let read = stream.read_to_end(&mut reply);
    let sent = if reply.is_empty() { sent } else { Ok(()) };
    sent.and(read).or_else(|e| match e.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
            let secs = kithd.timeout.as_secs();
            // A change that timed out may still have landed: say so rather than imply it did not.
            let maybe = if method == "GET" {
                ""
            } else {
                "; the change may still have been applied"
            };
            fail(format!(
                "kithd has not answered for {secs} s (--timeout sets how long to wait){maybe}"
            ))
        }
        _ => fail(format!("talking to kithd: {e}")),
    })?;

    let split = reply
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("error: kithd sent no reply")?;
    let head = String::from_utf8_lossy(&reply[..split]).to_ascii_lowercase();
    let body = &reply[split + 4..];
    if head.contains("transfer-encoding") {
        return fail("kithd sent a chunked reply, which this kith cannot read");
    }
    let ok = head.split(' ').nth(1).is_some_and(|status| status.starts_with('2'));
    if !ok {
        return fail(refusal(body));
    }
    // (A reply cut short is not the reply: a blob that came through another node, say.)
    let said = head.lines().find_map(|line| line.strip_prefix("content-length:"));
    if said
        .and_then(|length| length.trim().parse().ok())
        .is_some_and(|length: usize| length != body.len())
    {
        return fail("kithd's reply was cut short");
    }
    Ok(body.to_vec())
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    let timeout = std::time::Duration::from_secs(cli.timeout);
    let backend = || {
        // A named context always counts; the file's current one only when no flag says where kithd is.
        let wanted = cli.context.is_some() || (cli.store.is_none() && cli.server.is_none() && cli.socket.is_none());
        let chosen = match (wanted, cli.context.is_some()) {
            (true, true) => context::pick(&context::file()?, cli.context.as_deref())?,
            // (The file's own current context is not asked for: one that cannot be read is said, and kith goes on without it.)
            (true, false) => context::file()
                .and_then(|file| context::pick(&file, None))
                .unwrap_or_else(|e| {
                    eprintln!("kith: {e} (going on without a context)");
                    None
                }),
            (false, _) => None,
        };
        // (An explicit --socket is not sent to a context's server.)
        let chosen = chosen.filter(|_| cli.socket.is_none());
        if let (Some(c), None) = (&chosen, &cli.context) {
            static SAID: std::sync::Once = std::sync::Once::new();
            SAID.call_once(|| eprintln!("kith: using the current context's server {}", c.server));
        }
        let server = cli.server.clone().or_else(|| chosen.as_ref().map(|c| c.server.clone()));
        let identity = cli.identity.clone().or_else(|| chosen.map(|c| c.identity));
        match (&cli.store, server, cli.socket.clone().or_else(kith_api::default_socket)) {
            (Some(path), _, _) => Ok(Backend::Local(path.clone())),
            (None, Some(server), _) => match identity {
                Some(identity) => Ok(Backend::Daemon(Kithd {
                    route: Route::Node { server, identity },
                    timeout,
                })),
                None => fail("--server needs --identity DIR: the identity kithd is to see (kith identity makes one)"),
            },
            (None, None, Some(socket)) => Ok(Backend::Daemon(Kithd {
                route: Route::Socket(socket),
                timeout,
            })),
            (None, None, None) => {
                fail("no kithd socket: set --socket, --server or --context, or --store for a store file")
            }
        }
    };
    match cli.command {
        Command::Context { command } => {
            let file = context::file()?;
            match command {
                ContextCommand::Add { name, server, identity } => context::add(&file, &name, &server, &identity)?,
                ContextCommand::Use { name } => context::use_(&file, &name)?,
                ContextCommand::Rm { name } => context::rm(&file, &name)?,
                ContextCommand::Ls => print!("{}", context::ls(&file)?),
            }
            return Ok(ExitCode::SUCCESS);
        }
        Command::Import { command } => return import::run(command),
        #[cfg(feature = "docker")]
        Command::Docker {
            command: DockerCommand::Serve { listen },
        } => {
            let path = match listen.or_else(|| kith_api::default_socket().map(|s| s.with_file_name("docker.sock"))) {
                Some(path) => path,
                None => return fail("no place for the socket: set --listen PATH"),
            };
            // (The backend first: one that cannot be reached makes no socket.)
            let backend = backend()?;
            sign_before_serving(&backend)?;
            let store = docker_store::DockerStore(backend);
            let listener = kith_docker::listen(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            eprintln!(
                "kith: the Docker API is on {}: DOCKER_HOST=unix://{} docker version",
                path.display(),
                path.display()
            );
            kith_docker::serve_with(listener, Some(Box::new(store)));
            return Ok(ExitCode::SUCCESS);
        }
        Command::Machine { command } => return machine::run(command, &backend),
        Command::Lint { files } => {
            let n = load(&files)?.len();
            println!("{n} resource{} ok", if n == 1 { "" } else { "s" });
        }
        Command::Eval { file } => {
            let found = lang(&file, false).map_err(|wrong| wrong.join("\n"))?;
            let documents: Vec<String> = found.iter().map(kith_api::Resource::to_yaml).collect();
            print!("{}", documents.join("---\n"));
        }
        Command::Diff { files } => {
            let mut counts = [0; 3];
            for change in backend()?.apply(load(&files)?, true)? {
                counts[change.action as usize] += 1;
                let diff = change.diff();
                if !diff.is_empty() {
                    println!("{}", diff.trim_end_matches('\n'));
                }
            }
            eprintln!(
                "{} to create, {} to update, {} unchanged",
                counts[0], counts[1], counts[2]
            );
            return Ok(ExitCode::from(u8::from(counts[0] + counts[1] > 0)));
        }
        Command::Apply { files, dry_run } => {
            for change in backend()?.apply(load(&files)?, dry_run)? {
                let what = match change.action {
                    Action::Created => "created",
                    Action::Updated => "updated",
                    Action::Unchanged => "unchanged",
                };
                let revision = change.after.metadata.revision.unwrap_or(0);
                let dry = if dry_run { " (dry run)" } else { "" };
                println!("{} {what} (revision {revision}){dry}", change.after.key());
            }
        }
        Command::Get {
            target,
            name,
            namespace,
            output,
            watch,
        } => {
            let (kind_name, name) = match &target {
                Some(t) => match t.split_once('/') {
                    Some((kind, name)) => (Some(kind), Some(name.to_string())),
                    None => (Some(t.as_str()), name),
                },
                None => (None, None),
            };
            let info = kind_name.map(|name| Kind::find(name, &backend)).transpose()?;
            let single = name.is_some();
            if watch {
                let Backend::Daemon(kithd) = backend()? else {
                    return fail("-w needs kithd: it cannot watch a --store file");
                };
                if !matches!(output, Output::Table) {
                    return fail("-w prints a table: leave out -o");
                }
                let one = info
                    .as_ref()
                    .zip(name.as_deref())
                    .map(|(info, n)| info.key(n, namespace.as_deref()));
                let keep = |r: &Resource| match &one {
                    Some(one) => r.key() == *one,
                    None => namespace.is_none() || r.metadata.namespace == namespace,
                };
                return watch_get(&kithd, info.as_ref().map(|i| i.kind.as_str()), keep);
            }
            let found: Vec<Resource> = match (&info, name) {
                (Some(info), Some(name)) => vec![backend()?.get(&info.key(&name, namespace.as_deref()))?],
                (info, _) => {
                    let mut all = backend()?.list(info.as_ref().map(|i| i.kind.as_str()))?;
                    all.retain(|r| namespace.is_none() || r.metadata.namespace == namespace);
                    all
                }
            };
            match output {
                Output::Yaml => {
                    let docs: Vec<String> = found.iter().map(|r| r.to_yaml()).collect();
                    if !docs.is_empty() {
                        println!("{}", docs.join("---\n").trim_end());
                    }
                }
                // One named resource is an object; a listing is an array.
                Output::Json if single => println!("{}", serde_json::to_string_pretty(&found[0]).or_else(fail)?),
                Output::Json => println!("{}", serde_json::to_string_pretty(&found).or_else(fail)?),
                // A kind with columns of its own (a KindDefinition's) shows those.
                Output::Table if info.as_ref().is_some_and(|info| !info.columns.is_empty()) => {
                    let columns = &info.as_ref().expect("checked").columns;
                    let titles: Vec<String> = columns.iter().map(|(name, _)| name.to_uppercase()).collect();
                    let header = ["NAMESPACE", "NAME", "REVISION"]
                        .into_iter()
                        .chain(titles.iter().map(String::as_str));
                    let row = |r: &Resource| {
                        let whole = serde_json::to_value(r).unwrap_or_default();
                        let cell =
                            |(_, path): &(String, String)| match path.split('.').fold(&whole, |at, part| &at[part]) {
                                serde_json::Value::Null => String::new(),
                                serde_json::Value::String(text) => text.replace(char::is_control, ""),
                                other => other.to_string(),
                            };
                        let m = &r.metadata;
                        let own = [
                            m.namespace.clone().unwrap_or_default(),
                            m.name.clone(),
                            m.revision.unwrap_or(0).to_string(),
                        ];
                        own.into_iter().chain(columns.iter().map(cell)).collect()
                    };
                    print_rows(
                        &header.collect::<Vec<_>>(),
                        &found.iter().map(row).collect::<Vec<Vec<String>>>(),
                    );
                }
                Output::Table => {
                    let rows = found.iter().map(table_row);
                    print_table(["KIND", "NAMESPACE", "NAME", "REVISION", "STATUS"], rows.collect());
                    // (While the cluster holds nodes' keys and nobody was shown a recovery
                    // key of any; a kithd from before this, or one that refuses, says nothing.)
                    if let (Some("Node"), Ok(Backend::Daemon(kithd))) =
                        (info.as_ref().map(|i| i.kind.as_str()), backend())
                    {
                        let said = request::<serde_json::Value>(&kithd, "GET", "/v1/lock", b"").ok();
                        if let Some(warning) = said.as_ref().and_then(|said| said["warning"].as_str()) {
                            eprintln!("warning: {warning}");
                        }
                    }
                }
            }
        }
        Command::Delete { target } => {
            let key = target.key(&backend)?;
            backend()?.delete(&key)?;
            println!("{key} deleted");
        }
        Command::Run { on, via, argv } => {
            let Backend::Daemon(kithd) = backend()? else {
                return fail("remote apps go through kithd: leave out --store");
            };
            remote::watch();
            return remote::run(&kithd, &on, via.as_deref(), &argv);
        }
        Command::Logs {
            target,
            unit,
            replica,
            stderr,
            previous,
            tail,
            follow,
        } => {
            let Backend::Daemon(kithd) = backend()? else {
                return fail("logs are kept by kithd: leave out --store");
            };
            let mut path = format!("/v1/logs/{}?replica={replica}", escape(&target.key(&backend)?));
            for (flag, option) in [(stderr, "&stderr=true"), (previous, "&previous=true")] {
                path += if flag { option } else { "" };
            }
            if let Some(unit) = unit {
                path += &format!("&unit={}", escape(&unit));
            }
            stream_logs(&kithd, &path, tail, follow, &mut std::io::stdout())?;
        }
        Command::Launch(launch) => return launch::launch(launch, &backend()?),
        Command::Ps(ps) => launch::ps(&ps, &backend()?)?,
        Command::History { target } => {
            let history = backend()?.history(&target.key(&backend)?)?;
            let rows = history.iter().map(|r| {
                let m = &r.resource.metadata;
                [m.revision.unwrap_or(0).to_string(), rfc3339(r.at)]
            });
            print_table(["REVISION", "APPLIED"], rows.collect());
        }
        Command::Rollback { target, to } => {
            let key = target.key(&backend)?;
            let change = backend()?.rollback(&key, to)?;
            match change.action {
                Action::Unchanged => println!("{key} already matches revision {to}"),
                _ => println!(
                    "{key} rolled back to revision {to} (now revision {})",
                    change.after.metadata.revision.unwrap_or(0)
                ),
            }
        }
        Command::Switch {
            claim,
            workload,
            namespace,
        } => {
            let backend = backend()?;
            let namespace = namespace.as_deref().unwrap_or(DEFAULT_NAMESPACE);
            let (kind, name) = workload.split_once('/').unwrap_or(("Workload", workload.as_str()));
            let holder = format!("{kind}/{name}");
            // (The revision it came with stays: a change made meanwhile is refused, not overwritten.)
            let key = format!("DeviceClaim/{namespace}/{claim}");
            let mut resource = backend.get(&key)?;
            resource.spec["holder"] = serde_json::json!(holder);
            let switched = resource.validated().or_else(fail)?;
            // (A holder that is not there would switch nothing: say so instead.)
            backend
                .get(&format!("{kind}/{namespace}/{name}"))
                .map_err(|e| format!("{holder}: {e}"))?;
            let applied = backend.apply(vec![switched], false).map_err(|e| {
                if e.contains("is at revision") {
                    format!("{key}: the claim changed meanwhile: run it again")
                } else {
                    e
                }
            })?;
            for change in applied {
                let revision = change.after.metadata.revision.unwrap_or(0);
                println!(
                    "{} asks for {holder} (revision {revision}): `kith get deviceclaim {claim}` shows who holds it",
                    change.after.key()
                );
            }
        }
        Command::Backup {
            command: BackupCommand::Restore { name, namespace, at },
        } => {
            let Backend::Daemon(kithd) = backend()? else {
                return fail("a backup is restored by kithd: leave out --store");
            };
            let at = at.map_or(String::new(), |at| format!("?at={at}"));
            let path = format!("/v1/backups/{}/{}/restore{at}", escape(&namespace), escape(&name));
            let done: serde_json::Value = request(&kithd, "POST", &path, b"")?;
            println!(
                "{name}: the backup made at {} is back in volume {} on node {}",
                done["restored"]["at"],
                done["volume"].as_str().unwrap_or_default(),
                done["node"].as_str().unwrap_or_default()
            );
        }
        Command::Image {
            command: ImageCommand::Scan { image, node },
        } => {
            let Backend::Daemon(kithd) = backend()? else {
                return fail("an image is scanned by the node that has it: leave out --store");
            };
            let path = format!("/v1/scan/{}?image={}", escape(&node), escape(&image));
            let said: serde_json::Value = request(&kithd, "GET", &path, b"")?;
            print!("{}", scan_said(&said));
        }
        Command::Blob { command } => {
            let Backend::Daemon(kithd) = backend()? else {
                return fail("blobs are kept by kithd: leave out --store");
            };
            // ponytail: a blob passes through memory whole, as a netboot image does;
            // stream it when blobs outgrow that.
            match command {
                BlobCommand::Put {
                    file,
                    namespace,
                    copies,
                } => {
                    let bytes = std::fs::read(&file).or_else(|e| fail(format!("{}: {e}", file.display())))?;
                    let copies = copies.map_or(String::new(), |copies| format!("&copies={copies}"));
                    let path = format!("/v1/blobs?namespace={}{copies}", escape(&namespace));
                    let kept: serde_json::Value = request(&kithd, "PUT", &path, &bytes)?;
                    println!("{}", kept["name"].as_str().unwrap_or_default());
                }
                BlobCommand::Get {
                    name,
                    namespace,
                    output,
                } => {
                    use std::io::Write;
                    let path = format!("/v1/blobs/{}/{}", escape(&namespace), escape(&name));
                    let bytes = raw(&kithd, "GET", &path, b"")?;
                    let written = match &output {
                        Some(file) => std::fs::write(file, &bytes),
                        None => std::io::stdout().write_all(&bytes),
                    };
                    written.or_else(|e| fail(format!("writing the blob: {e}")))?;
                }
            }
        }
        Command::Volume { command } => {
            use std::process::Stdio;
            let Backend::Daemon(kithd) = backend()? else {
                return fail("a volume's files are kept by kithd: leave out --store");
            };
            let no_tar = |e: std::io::Error| {
                fail(format!(
                    "running tar: {e}\nkith uses this machine's tar: with none, give - as PATH and pipe a tar"
                ))
            };
            let route =
                |namespace: &str, name: &str| format!("/v1/volumes/{}/{}/files", escape(namespace), escape(name));
            match command {
                VolumeCommand::Put { name, path, namespace } => {
                    let route = route(&namespace, &name);
                    let done = if path.as_os_str() == "-" {
                        STDIN_WAS_INPUT.store(true, std::sync::atomic::Ordering::SeqCst);
                        carry(&kithd, "PUT", &route, Some(&mut std::io::stdin().lock()), None)?
                    } else {
                        // A directory's content, or the one file, under the name it has.
                        let found = std::fs::metadata(&path).or_else(|e| fail(format!("{}: {e}", path.display())))?;
                        let named = path.file_name().filter(|_| !found.is_dir());
                        let (dir, what) = match named {
                            Some(name) => (path.parent().unwrap_or(Path::new("")), Path::new(".").join(name)),
                            None => (path.as_path(), PathBuf::from(".")),
                        };
                        let dir = if dir.as_os_str().is_empty() {
                            Path::new(".")
                        } else {
                            dir
                        };
                        let packing = tar("-cf", dir).arg(what).stdout(Stdio::piped()).spawn();
                        let mut packing = packing.or_else(no_tar)?;
                        let packed = packing.stdout.take().expect("it was asked for");
                        carry(&kithd, "PUT", &route, Some(&mut Piped(packing, packed)), None)?
                    };
                    let done: serde_json::Value =
                        serde_json::from_slice(&done).or_else(|e| fail(format!("reading kithd's reply: {e}")))?;
                    for link in done["leftOut"].as_array().into_iter().flatten() {
                        let link = link.as_str().unwrap_or_default();
                        eprintln!("left out, a link that points out of the volume: {link}");
                    }
                    println!(
                        "{} files ({} bytes) are in volume {name} on node {}",
                        done["files"],
                        done["bytes"],
                        done["node"].as_str().unwrap_or_default()
                    );
                }
                VolumeCommand::Get { name, path, namespace } => {
                    let route = route(&namespace, &name);
                    if path.as_os_str() == "-" {
                        carry(&kithd, "GET", &route, None, Some(&mut std::io::stdout().lock()))?;
                    } else {
                        std::fs::create_dir_all(&path).or_else(|e| fail(format!("{}: {e}", path.display())))?;
                        let unpacking = tar("-xf", &path).stdin(Stdio::piped()).spawn();
                        let mut unpacking = unpacking.or_else(no_tar)?;
                        let mut into = unpacking.stdin.take().expect("it was asked for");
                        let got = carry(&kithd, "GET", &route, None, Some(&mut into));
                        drop(into);
                        let unpacked = unpacking.wait();
                        got?;
                        if !unpacked.is_ok_and(|unpacked| unpacked.success()) {
                            return fail("tar did not unpack all of it (it says why above)");
                        }
                    }
                }
            }
        }
        Command::Node {
            command: NodeCommand::Token { worker, ingress },
        } => {
            let Backend::Daemon(kithd) = backend()? else {
                return fail("tokens are made by kithd: leave out --store");
            };
            let route = match (worker, ingress) {
                (true, true) => "/v1/tokens?trust=worker&store=whole",
                (true, false) => "/v1/tokens?trust=worker",
                _ => "/v1/tokens",
            };
            let reply: serde_json::Value = request(&kithd, "POST", route, b"")?;
            println!("{}", reply["token"].as_str().unwrap_or_default());
        }
        Command::Node {
            command:
                NodeCommand::Netboot {
                    image,
                    mac,
                    minutes,
                    disk,
                    encrypt,
                    off,
                },
        } => {
            let Backend::Daemon(kithd) = backend()? else {
                return fail("machines are installed by kithd: leave out --store");
            };
            let now: serde_json::Value = match (image, off) {
                (Some(image), _) => {
                    let file = std::fs::read(&image).or_else(|e| fail(format!("{}: {e}", image.display())))?;
                    let path = format!(
                        "/v1/netboot?macs={}&minutes={minutes}&disk={disk}&encrypt={encrypt}",
                        mac.join(",")
                    );
                    request(&kithd, "PUT", &path, &file)?
                }
                (None, true) => request(&kithd, "DELETE", "/v1/netboot", b"")?,
                (None, false) => request(&kithd, "GET", "/v1/netboot", b"")?,
            };
            match now["on"].as_bool() {
                Some(true) => {
                    println!(
                        "netboot is on for {} more minutes",
                        now["secondsLeft"].as_u64().unwrap_or(0).div_ceil(60)
                    );
                    for machine in now["machines"].as_array().into_iter().flatten() {
                        let served = machine["served"].as_bool().unwrap_or(false);
                        let mac = machine["mac"].as_str().unwrap_or_default();
                        println!("  {mac}  {}", if served { "has the installer" } else { "not seen yet" });
                    }
                }
                _ => println!("netboot is off"),
            }
        }
        Command::Node {
            command:
                command @ (NodeCommand::Lock { .. }
                | NodeCommand::Unlock { .. }
                | NodeCommand::Seal { .. }
                | NodeCommand::Wipe { .. }),
        } => {
            let Backend::Daemon(kithd) = backend()? else {
                return fail("keys are held by kithd: leave out --store");
            };
            let (name, what) = match command {
                NodeCommand::Lock { name } => (name, "lock"),
                NodeCommand::Unlock { name } => (name, "unlock"),
                NodeCommand::Seal { name, off } => (name, if off { "unseal" } else { "seal" }),
                NodeCommand::Wipe { name, erase } if name == erase => (name, "wipe"),
                _ => return fail("--erase is not the node's name: nothing was done"),
            };
            let _: serde_json::Value = request(&kithd, "POST", &format!("/v1/lock/{name}?do={what}"), b"")?;
            println!(
                "{}",
                match what {
                    "lock" => format!("{name} is locked: it restarts, and waits until `kith node unlock {name}`"),
                    "unlock" => format!("{name} is unlocked: it is handed its key when it asks"),
                    "seal" => format!(
                        "{name} may seal the key of its state to its own TPM: `kith get NodeKey {name}` says once it has, or why not"
                    ),
                    "unseal" => format!(
                        "{name} drops its TPM's seal when it hears of it: from then on it asks the cluster for its key"
                    ),
                    _ => format!("{name} is wiped: the cluster has forgotten the key of its state"),
                }
            );
        }
        Command::Peer {
            command:
                PeerCommand::Add {
                    name,
                    node,
                    level,
                    replace,
                },
        } => {
            let Backend::Daemon(kithd) = backend()? else {
                return fail("keys are made by kithd: leave out --store");
            };
            let body = serde_json::json!({"name": name, "node": node, "level": level, "replace": replace});
            let made = request::<serde_json::Value>(&kithd, "POST", "/v1/peers", body.to_string().as_bytes())?;
            print!("{}", peer_text(&made)?);
        }
        Command::Node {
            command: NodeCommand::Recovery { name },
        } => {
            let Backend::Daemon(kithd) = backend()? else {
                return fail("keys are held by kithd: leave out --store");
            };
            // (The node writes the new key before it answers: an answer that is lost on
            // its way leaves a key nobody was shown, and the old one opens no more.)
            let made = request::<serde_json::Value>(&kithd, "POST", &format!("/v1/lock/{name}/recovery"), b"{}");
            let made = made.map_err(|e| {
                format!("{e}\nNo recovery key was shown. If {name} made one before this failed, the key it had opens it no more: run this again while {name} runs.")
            })?;
            println!(
                "{name}'s recovery key, shown this once and kept nowhere: write it down. Typed at {name}'s console when it starts and no node hands its key out, it opens its state; the key {name} had before opens it no more.\n\n    {}\n",
                made["recovery"].as_str().unwrap_or_default()
            );
        }
        Command::Node {
            command: NodeCommand::Encrypt { name, cancel },
        } => {
            let Backend::Daemon(kithd) = backend()? else {
                return fail("keys are held by kithd: leave out --store");
            };
            // (The node writes its record and marker before it answers, and restarts after: an
            // answer lost on the way leaves the marker, which `--cancel` takes away until it starts.)
            let body = serde_json::json!({ "cancel": cancel });
            let said = request::<serde_json::Value>(
                &kithd,
                "POST",
                &format!("/v1/lock/{name}/encrypt"),
                body.to_string().as_bytes(),
            )?;
            print!("{}", encrypt_text(&name, cancel, &said)?);
        }
        Command::Node {
            command: NodeCommand::Duress { name, all, off },
        } => {
            let Backend::Daemon(kithd) = backend()? else {
                return fail("keys are held by kithd: leave out --store");
            };
            let path = match (&name, off) {
                (Some(name), _) => format!("/v1/lock/{name}?do={}", if off { "no-duress" } else { "duress" }),
                (None, true) => "/v1/duress?off".to_string(),
                (None, false) => "/v1/duress".to_string(),
            };
            let made: serde_json::Value = request(&kithd, "POST", &path, b"")?;
            let nodes: Vec<&str> = made["nodes"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|node| node.as_str())
                .collect();
            let whose = name.clone().unwrap_or(nodes.join(", "));
            let code = made["code"].as_str().unwrap_or_default();
            println!(
                "{}",
                match (all, off) {
                    (_, true) => format!("{whose}: no duress code from when each hears of it"),
                    (false, false) => format!(
                        "A duress code for {whose}, shown this once and kept nowhere:\n\n    {code}\n\nTyped at {whose}'s console while it waits for its key, it erases what the disk opens with (its recovery key and passphrase open it no more) and has the cluster forget its key; the console says what it says of a wrong key. There is no way back, and a disk copied beforehand, with its recovery key, still opens. Take the code away with --off."
                    ),
                    (true, false) => format!(
                        "A duress code for the whole cluster ({whose}), shown this once and kept nowhere:\n\n    {code}\n\nTyped at the waiting console of any of them, it erases what that node's disk opens with and has the cluster forget the key of every one of them: the others run on, and open from then on with their own recovery keys alone, until `kith node unlock NAME`. A node that joins later is not under it. Take the code away with --all --off."
                    ),
                }
            );
        }
        Command::Node {
            command: NodeCommand::Drain { name, dry_run },
        } => {
            let Backend::Daemon(kithd) = backend()? else {
                return fail("drains are planned by kithd: leave out --store");
            };
            // kithd works out what the drain does; this only says it, before anything changes.
            let plan: Vec<serde_json::Value> = request(&kithd, "GET", &format!("/v1/drain/{name}"), b"")?;
            for line in drain_text(&name, &plan) {
                println!("{line}");
            }
            if dry_run {
                println!("dry run: nothing changed");
            } else {
                let _: serde_json::Value = request(&kithd, "POST", &format!("/v1/drain/{name}?do=drain"), b"")?;
                println!("{name} is drained: its replicas above move, and nothing new is placed on it");
            }
        }
        Command::Node {
            command: NodeCommand::Undrain { name },
        } => {
            let Backend::Daemon(kithd) = backend()? else {
                return fail("drains are set by kithd: leave out --store");
            };
            let _: serde_json::Value = request(&kithd, "POST", &format!("/v1/drain/{name}?do=undrain"), b"")?;
            println!("{name} takes replicas again: the replicas that moved off it are not moved back");
        }
        Command::Node {
            command: NodeCommand::Passphrase { name, off },
        } => {
            let Backend::Daemon(kithd) = backend()? else {
                return fail("keys are held by kithd: leave out --store");
            };
            let passphrase = match off {
                true => None,
                false => Some(secret(&format!("A passphrase for {name}'s state: "), true)?),
            };
            let body = serde_json::json!({ "passphrase": passphrase }).to_string();
            let _: serde_json::Value =
                request(&kithd, "POST", &format!("/v1/lock/{name}/passphrase"), body.as_bytes())?;
            println!(
                "{}",
                match off {
                    true => format!("{name} has no passphrase: it asks the cluster for the key of its state"),
                    false => format!(
                        "{name} opens its state with that passphrase, typed at its console when it starts and no node answers (as its keys lie at start: the kernel's own layout, US). Take it away with --off"
                    ),
                }
            );
        }
        Command::Node {
            command: NodeCommand::Disk { command },
        } => {
            let Backend::Daemon(mut kithd) = backend()? else {
                return fail("disks are added by kithd: leave out --store");
            };
            match command {
                DiskCommand::Add {
                    node,
                    serial,
                    wipe,
                    quick,
                } => {
                    // (Zeroing a disk through its encryption takes as long as writing the disk.)
                    kithd.timeout = kithd.timeout.max(std::time::Duration::from_secs(24 * 3600));
                    let body = serde_json::json!({ "serial": serial, "wipe": wipe, "quick": quick }).to_string();
                    let said: serde_json::Value =
                        request(&kithd, "POST", &format!("/v1/disks/{node}"), body.as_bytes())?;
                    let (id, disk) = (said["id"].as_str().unwrap_or("?"), said["disk"].as_str().unwrap_or("?"));
                    println!("{node}: {disk} (serial {serial}) is now a data disk, id {id}");
                    match said["why"].as_str() {
                        Some(why) => println!("{why}"),
                        None => println!("it is mounted: the node mounts it at every start"),
                    }
                }
                DiskCommand::Remove { node, id } => {
                    let said: serde_json::Value = request(&kithd, "DELETE", &format!("/v1/disks/{node}/{id}"), b"")?;
                    match said["absent"].as_bool() {
                        Some(true) => println!(
                            "{node}: disk {id} was not in the machine: it is no longer a data disk, its key is forgotten and nothing could be zeroed"
                        ),
                        _ => println!(
                            "{node}: disk {id} is no longer a data disk: its header is zeroed and its key forgotten"
                        ),
                    }
                }
                DiskCommand::List { node } => {
                    let said: serde_json::Value = request(&kithd, "GET", &format!("/v1/disks/{node}"), b"")?;
                    print!("{}", disks_said(&said));
                }
            }
        }
        Command::Node {
            command: NodeCommand::Pin { name, untried_tpm, off },
        } => {
            let Backend::Daemon(kithd) = backend()? else {
                return fail("keys are held by kithd: leave out --store");
            };
            if !off && !untried_tpm {
                return fail(
                    "a PIN has run against a software TPM only, never yet against a machine's own: run \"On hardware: the owner's checklist\" in docs/adr-unlock.md on it, then give the PIN with --untried-tpm. Know first: where the TPM's lockout authorization is empty, kithd takes the TPM's lockout authorization and keeps it only in the node's encrypted state; if that state is lost, only clearing the TPM gives it back. And each setting of a PIN tries one wrong PIN, which the TPM counts. Make the PIN random digits: a date or 123456 is among the first guesses",
                );
            }
            // (Read here, unseen, never from the command line; for the kithd asked, which takes
            // it for itself alone and passes it on to no node.)
            let pin = match off {
                true => None,
                false => Some(secret(&format!("A PIN for {name}'s state, 6 to 32 digits: "), true)?),
            };
            let body = serde_json::json!({ "pin": pin, "untried": untried_tpm }).to_string();
            let said: serde_json::Value = request(&kithd, "POST", &format!("/v1/lock/{name}/pin"), body.as_bytes())?;
            match said["lockout"].as_str() {
                Some(lockout) => println!(
                    "{name} opens its state with its TPM and that PIN, typed at its console when it starts, or with the cluster's key as before; its TPM alone no longer does. {lockout}. Take it away with --off"
                ),
                None => println!("{name} has no PIN: it asks the cluster for the key of its state"),
            }
        }
        Command::Admin {
            command: AdminCommand::Key,
        } => {
            let backend = backend()?;
            let Backend::Daemon(kithd) = &backend else {
                return fail("the admin's key is set through kithd: leave out --store");
            };
            let status: serde_json::Value = request(kithd, "GET", "/v1/cluster", b"")?;
            let Some(cluster_id) = status["clusterId"].as_str() else {
                return fail("kithd gave no cluster id to derive the key with: update kithd");
            };
            let passphrase = admin_passphrase("A passphrase for the admin's key: ", true)?;
            let public = signing::public(&signing::key(&passphrase, cluster_id));
            // (The write below is signed with this same passphrase: the key it sets, if it is the one there.)
            let _ = PASSPHRASE.set(passphrase);
            let clusters = backend.list(Some("Cluster"))?;
            let [mut cluster] = <[Resource; 1]>::try_from(clusters)
                .map_err(|all| format!("error: {} Clusters: exactly one is needed to set its key", all.len()))?;
            cluster.spec["adminKey"] = serde_json::json!(public);
            backend.apply(vec![cluster], false)?;
            println!("The Cluster's spec.adminKey is set: writes signed with this passphrase are its admin's");
        }
        Command::Identity {
            command: IdentityCommand::Cert { name, out },
        } => {
            let Backend::Daemon(kithd) = backend()? else {
                return fail("certificates are made by kithd: leave out --store");
            };
            let made: serde_json::Value = request(&kithd, "POST", &format!("/v1/identities/{name}/certificate"), b"")?;
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            for (file, part) in [
                (format!("{name}.key"), "key"),
                (format!("{name}.crt"), "cert"),
                ("ca.crt".into(), "ca"),
            ] {
                let path = out.join(file);
                // (The mode is for the key; it does the others no harm.)
                let mut options = std::fs::OpenOptions::new();
                let opened = options.write(true).create(true).truncate(true).mode(0o600).open(&path);
                let text = made[part].as_str().unwrap_or_default();
                let written = opened.and_then(|mut file| file.write_all(text.as_bytes()));
                written.map_err(|e| format!("error: writing {}: {e}", path.display()))?;
            }
            let out = out.display();
            println!(
                "Identity/{name} can call the API with {out}/{name}.crt and {out}/{name}.key (nodes show {out}/ca.crt, as `kith`)"
            );
            println!("It may do what Roles bound to it allow: nothing, until a RoleBinding names it.");
        }
        Command::Ca {
            command: CaCommand::Export { file },
        } => {
            let Backend::Daemon(kithd) = backend()? else {
                return fail("the CA is kithd's: leave out --store");
            };
            let on_the_node = "kith ca export runs on the node that holds the CA (kithd's admin socket serves the certificate, no remote context does)";
            if matches!(kithd.route, Route::Node { .. }) {
                return fail(format!("error: {on_the_node}"));
            }
            let reply = raw(&kithd, "GET", "/v1/ca/lan", b"").map_err(|e| format!("{e}\n(note: {on_the_node})"))?;
            let pem = String::from_utf8(reply).map_err(|_| "error: kithd's reply is not text".to_string())?;
            // (A certificate and nothing else: what is written for the world to trust holds no key.)
            if pem.contains("PRIVATE KEY") || !pem.contains("BEGIN CERTIFICATE") {
                return fail("kithd's reply is not a certificate alone (a private key is never exported)");
            }
            match file {
                Some(file) => {
                    std::fs::write(&file, &pem).map_err(|e| format!("error: writing {}: {e}", file.display()))?;
                    println!(
                        "The LAN CA's certificate is in {}: trust it once on each device (it vouches only for the cluster's LAN names)",
                        file.display()
                    );
                }
                None => print!("{pem}"),
            }
        }
        Command::Controller {
            command:
                ControllerCommand::Set {
                    kind,
                    controller,
                    admission,
                },
        } => {
            if controller.is_none() && admission.is_none() {
                return fail("give --controller FILE, --admission FILE or both");
            }
            let backend = backend()?;
            let definitions = backend.list(Some("KindDefinition"))?;
            let named = |definition: &Resource| {
                definition.spec["kind"]
                    .as_str()
                    .is_some_and(|k| k.eq_ignore_ascii_case(&kind))
            };
            let Some(mut definition) = definitions.into_iter().find(named) else {
                return fail(format!("no KindDefinition makes a kind `{kind}`"));
            };
            let mut said = Vec::new();
            for (role, file) in [("controller", controller), ("admission", admission)] {
                let Some(file) = file else { continue };
                let module = std::fs::read(&file).map_err(|e| format!("error: reading {}: {e}", file.display()))?;
                definition.spec[role] = serde_json::json!({ "wasm": base64(&module) });
                said.push(format!(
                    "{}: {role} is {} ({} bytes)",
                    definition.key(),
                    file.display(),
                    module.len()
                ));
            }
            definition.status = None;
            backend.apply(vec![definition], false)?;
            println!("{}", said.join("\n"));
        }
        Command::Ui { port } => {
            let Backend::Daemon(kithd) = backend()? else {
                return fail("the web UI is kithd's: leave out --store");
            };
            ui::serve(&kithd.route, port)?;
        }
        Command::Audit { tail } => {
            let Backend::Daemon(kithd) = backend()? else {
                return fail("the audit log is kithd's: leave out --store");
            };
            let entries: Vec<serde_json::Value> = request(&kithd, "GET", &format!("/v1/audit?tail={tail}"), b"")?;
            let text = |value: &serde_json::Value| value.as_str().unwrap_or_default().to_string();
            let rows = entries.iter().map(|entry| {
                let what = entry["what"].as_array().into_iter().flatten().map(text);
                let outcome = if entry["ok"] == true {
                    "ok".into()
                } else {
                    text(&entry["error"])
                };
                let at = rfc3339(entry["at"].as_u64().unwrap_or(0));
                [
                    at,
                    text(&entry["who"]),
                    text(&entry["verb"]),
                    what.collect::<Vec<_>>().join(" "),
                    outcome,
                ]
            });
            print_table(["WHEN", "WHO", "DID", "WHAT", "OUTCOME"], rows.collect());
        }
        Command::Node {
            command: NodeCommand::Features { name },
        } => {
            let node = backend()?.get(&format!("Node/{name}"))?;
            print!("{}", features_spec(&node)?);
        }
        Command::Node {
            command: NodeCommand::Status,
        } => {
            let Backend::Daemon(kithd) = backend()? else {
                return fail("only kithd knows: leave out --store");
            };
            let reply: serde_json::Value = request(&kithd, "GET", "/v1/cluster", b"")?;
            let names = |value: &serde_json::Value| {
                let names = value.as_array().into_iter().flatten().filter_map(|name| name.as_str());
                names.collect::<Vec<_>>().join(", ")
            };
            if let Some(view) = reply.get("view") {
                // A worker keeps no store: it leads nothing and has no vote to speak of.
                println!(
                    "this node: {}, a worker: its view of the store is at change {}, sent by {}",
                    reply["node"].as_str().unwrap_or_default(),
                    view["applied"],
                    view["from"].as_str().unwrap_or("no control node yet")
                );
            } else {
                println!("leader:    {}", reply["leader"].as_str().unwrap_or("none"));
                println!("voters:    {}", names(&reply["voters"]));
                println!("receiving: {}", names(&reply["learners"]));
                println!(
                    "this node: {}, change {}",
                    reply["node"].as_str().unwrap_or_default(),
                    reply["applied"]
                );
            }
            for peer in reply["mesh"].as_array().into_iter().flatten() {
                let shook = match peer["handshake"].as_u64() {
                    Some(ago) => format!("handshake {ago} s ago"),
                    None => "no handshake yet".into(),
                };
                let how = match (peer["relayed"] == true, peer["reached"] == false) {
                    (true, _) => ", through an edge node",
                    (false, true) => ", unreachable",
                    (false, false) => ", direct",
                };
                let (node, address) = (peer["node"].as_str(), peer["address"].as_str());
                println!(
                    "mesh:      {} at {}, {shook}{how}",
                    node.unwrap_or_default(),
                    address.unwrap_or_default()
                );
            }
        }
        Command::Package {
            command:
                PackageCommand::Render {
                    dir,
                    name,
                    namespace,
                    values,
                    set,
                },
        } => {
            let package = load_package(&dir)?;
            let mut layers = Vec::new();
            for path in &values {
                let source = std::fs::read_to_string(path).or_else(|e| fail(format!("{}: {e}", path.display())))?;
                let layer = kith_yaml::from_str(&source).map_err(|e| e.render(&path.display().to_string(), &source))?;
                layers.push(layer);
            }
            for assignment in &set {
                layers.push(set_value(assignment)?);
            }
            let release = kith_packages::Release {
                name: name.as_deref().unwrap_or(&package.meta.name),
                namespace: &namespace,
            };
            let rendered = package.render(release, &layers).or_else(fail)?;
            let documents: Vec<String> = rendered.resources.iter().map(kith_api::Resource::to_yaml).collect();
            print!("{}", documents.join("---\n"));
            if let Some(notes) = rendered.notes {
                eprintln!("{}", notes.trim_end());
            }
        }
        Command::Package {
            command: PackageCommand::Lint { dir },
        } => {
            let package = kith_packages::Package::load(&dir).or_else(fail)?;
            let wrong = package.lint();
            if !wrong.is_empty() {
                return fail(wrong.join("\n"));
            }
            println!("{} {} ok", package.meta.name, package.meta.version);
        }
        Command::Package {
            command: PackageCommand::Push { dir, to, key },
        } => {
            let package = load_package(&dir)?;
            let wrong = package.lint();
            if !wrong.is_empty() {
                return fail(wrong.join("\n"));
            }
            if let Some(to) = to {
                let signature = match key {
                    None => None,
                    Some(key) => {
                        let secret =
                            std::fs::read_to_string(&key).or_else(|e| fail(format!("{}: {e}", key.display())))?;
                        Some(package.sign(&secret).or_else(fail)?)
                    }
                };
                let asked = serde_json::json!({ "to": to, "files": package.files, "signature": signature });
                let pushed: String = backend()?.registry("push", &asked)?;
                let signed = if signature.is_some() { "signed" } else { "not signed" };
                println!("{pushed} pushed ({signed})");
                return Ok(ExitCode::SUCCESS);
            }
            for change in backend()?.apply(vec![package.resource().or_else(fail)?], false)? {
                let what = match change.action {
                    Action::Created => "created",
                    Action::Updated => "updated",
                    Action::Unchanged => "unchanged",
                };
                println!("{} {what}", change.after.key());
            }
        }
        Command::Package {
            command:
                PackageCommand::Pull {
                    from,
                    name,
                    version,
                    public_key,
                    output,
                },
        } => {
            let asked = serde_json::json!({ "from": from, "name": name, "version": version, "publicKey": public_key });
            let files: std::collections::BTreeMap<String, String> = backend()?.registry("pull", &asked)?;
            // (Checked here too: what is written is what this kith takes for a package.)
            let package = kith_packages::Package::from_files(files).or_else(fail)?;
            let dir = output.unwrap_or_else(|| PathBuf::from(format!("{name}-{version}")));
            let wrote = |path: &std::path::Path, done: std::io::Result<()>| {
                done.or_else(|e| fail(format!("{}: {e}", path.display())))
            };
            // (Never into a directory that is there: nothing of anyone's is written over.)
            wrote(&dir, std::fs::create_dir(&dir))?;
            for (path, text) in &package.files {
                let path = dir.join(path);
                let parent = path.parent().unwrap_or(&dir);
                wrote(parent, std::fs::create_dir_all(parent))?;
                wrote(&path, std::fs::write(&path, text))?;
            }
            let checked = if public_key.is_some() {
                "signature checked"
            } else {
                "signature not checked"
            };
            println!(
                "{} {} in {} ({checked})",
                package.meta.name,
                package.meta.version,
                dir.display()
            );
        }
        Command::Package {
            command: PackageCommand::Keygen { file },
        } => {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let (secret, public) = kith_packages::artifact::keygen().or_else(fail)?;
            // (A new file only its owner reads: a key is not written over, nor left open.)
            let made = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&file);
            let written = made.and_then(|mut made| writeln!(made, "{secret}"));
            written.or_else(|e| fail(format!("{}: {e}", file.display())))?;
            println!("{public}");
        }
        Command::Source {
            command: SourceCommand::Approve { name, namespace },
        } => {
            let backend = backend()?;
            let mut source = backend.get(&format!(
                "Source/{}/{name}",
                namespace.as_deref().unwrap_or(DEFAULT_NAMESPACE)
            ))?;
            let pending = source
                .status
                .as_ref()
                .and_then(|status| status["pending"]["revision"].as_str());
            let Some(revision) = pending.map(str::to_string) else {
                return fail(format!("{} has nothing waiting to be approved", source.key()));
            };
            source.spec["approve"] = serde_json::json!(revision);
            (source.metadata.revision, source.status) = (None, None);
            backend.apply(vec![source.validated().or_else(fail)?], false)?;
            println!("{name}: revision {revision} approved");
        }
        Command::Source {
            command: SourceCommand::Push { dir, to },
        } => {
            // (Files themselves, not links: nothing from elsewhere on this machine goes out.)
            fn read(
                dir: &std::path::Path,
                under: &str,
                files: &mut std::collections::BTreeMap<String, String>,
            ) -> std::io::Result<()> {
                for entry in std::fs::read_dir(dir)? {
                    let entry = entry?;
                    let name = format!("{under}{}", entry.file_name().to_string_lossy());
                    let kind = entry.file_type()?;
                    if kind.is_dir() {
                        read(&entry.path(), &format!("{name}/"), files)?;
                    } else if kind.is_file() && [".yaml", ".yml", ".json"].iter().any(|suffix| name.ends_with(suffix)) {
                        files.insert(name, std::fs::read_to_string(entry.path())?);
                    }
                }
                Ok(())
            }
            let mut files = std::collections::BTreeMap::new();
            read(&dir, "", &mut files).or_else(|e| fail(format!("{}: {e}", dir.display())))?;
            let Some((url, name)) = to.rsplit_once('/') else {
                return fail("--to is oci://HOST/PATH/NAME[:TAG]");
            };
            let (name, tag) = name.split_once(':').unwrap_or((name, "latest"));
            let count = files.len();
            let asked = serde_json::json!({ "to": url, "files": files, "source": [name, tag] });
            let pushed: String = backend()?.registry("push", &asked)?;
            println!("{pushed} pushed ({count} files)");
        }
        Command::Schema { kind: None } => {
            let rows = KINDS
                .iter()
                .map(|k| [k.kind, if k.namespaced { "namespaced" } else { "cluster" }, k.about].map(String::from));
            // (And the kinds the cluster's KindDefinitions make, when there is a cluster to ask.)
            let defined = backend()
                .and_then(|backend| backend.list(Some("KindDefinition")))
                .unwrap_or_default();
            let made = defined.iter().map(|d| {
                let text = |field: &str| d.spec[field].as_str().unwrap_or_default().replace(char::is_control, "");
                let scope = if d.spec["namespaced"] == false {
                    "cluster"
                } else {
                    "namespaced"
                };
                [
                    text("kind"),
                    scope.into(),
                    format!("{}/{} ({})", text("group"), text("version"), d.key()),
                ]
            });
            print_table(["KIND", "SCOPE", "ABOUT"], rows.chain(made).collect());
        }
        Command::Schema { kind: Some(name) } => {
            let schema = match kith_api::kind(&name) {
                Some(own) => own.schema(),
                None => Kind::find(&name, &backend)?.schema,
            };
            println!("{}", serde_json::to_string_pretty(&schema).or_else(fail)?);
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn table_row(r: &Resource) -> [String; 5] {
    let m = &r.metadata;
    [
        r.kind.clone(),
        m.namespace.clone().unwrap_or_default(),
        m.name.clone(),
        m.revision.unwrap_or(0).to_string(),
        status_summary(r),
    ]
}

/// `kith get -w`: the table, then each row that changes (a deleted one says so),
/// by long-polling `GET /v1/watch` until interrupted or kithd goes away.
fn watch_get(kithd: &Kithd, kind: Option<&str>, keep: impl Fn(&Resource) -> bool) -> Result<ExitCode, String> {
    #[derive(serde::Deserialize)]
    struct Watched {
        generation: u64,
        resources: Vec<Resource>,
    }
    // The reply must come back before --timeout, or every quiet minute would be an error.
    let wait = kithd.timeout.as_secs().saturating_sub(1).min(25);
    let kind = kind.map(|k| format!("&kind={k}")).unwrap_or_default();
    let mut shown = std::collections::BTreeMap::new();
    let mut after = None;
    loop {
        let path = match after {
            None => format!("/v1/watch?wait=0{kind}"),
            Some(g) => format!("/v1/watch?after={g}&wait={wait}{kind}"),
        };
        let now: Watched = match request(kithd, "GET", &path, b"") {
            Ok(now) => now,
            // A kithd too busy to answer in time has not changed anything we would miss: ask again.
            Err(e) if after.is_some() && e.contains("has not answered") => continue,
            Err(e)
                if after.is_some()
                    && (e.contains("cannot reach kithd")
                        || e.contains("sent no reply")
                        || e.contains("without closing TLS")) =>
            {
                return fail("kithd stopped");
            }
            Err(e) => return Err(e),
        };
        let rows: std::collections::BTreeMap<String, [String; 5]> = now
            .resources
            .iter()
            .filter(|r| keep(r))
            .map(|r| (r.key(), table_row(r)))
            .collect();
        if after.is_none() {
            print_table(
                ["KIND", "NAMESPACE", "NAME", "REVISION", "STATUS"],
                rows.values().cloned().collect(),
            );
        } else {
            // ponytail: changed rows are not aligned with the first table's columns
            for (key, row) in &rows {
                if shown.get(key) != Some(row) {
                    println!("{}", row.join("  ").trim_end());
                }
            }
            for (key, row) in &shown {
                if !rows.contains_key(key) {
                    println!("{}", [&row[0], &row[1], &row[2], "", "deleted"].join("  "));
                }
            }
        }
        shown = rows;
        if after == Some(now.generation) && wait == 0 {
            // --timeout 1: kithd answers at once, so do not spin.
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        after = Some(now.generation);
    }
}

/// How far an image pull is, as a container's `pull` says it: "pulling 3 of 7 layers, 12 of 40 MB".
fn pull_text(pull: &serde_json::Value) -> Option<String> {
    let said = |field: &str| pull[field].as_u64();
    let (layers, of, bytes, total) = (
        said("layers")?,
        said("layersTotal")?,
        said("bytes")?,
        said("bytesTotal")?,
    );
    let (unit, size) = [("GB", 1e9), ("MB", 1e6), ("KB", 1e3)]
        .into_iter()
        .find(|(_, size)| total as f64 >= *size)
        .unwrap_or(("B", 1.0));
    let show = |n: u64| match n as f64 / size {
        x if x >= 10.0 || size == 1.0 => format!("{x:.0}"),
        x => format!("{x:.1}"),
    };
    Some(format!(
        "pulling {layers} of {of} layers, {} of {} {unit}",
        show(bytes),
        show(total)
    ))
}

/// The STATUS column: what a controller reported, in a few words.
fn status_summary(resource: &Resource) -> String {
    // First line only, and nothing that could drive the terminal: messages quote image names and output.
    let clean = |m: &str| m.lines().next().unwrap_or_default().replace(char::is_control, "");
    // A Cluster's house address (T-0730): its endpoint, and which node holds it since when.
    if let (Some(address), "Cluster") = (resource.spec["home"]["address"].as_str(), resource.kind.as_str()) {
        let said = |value: &serde_json::Value| value.as_str().map(clean);
        let endpoint = said(&resource.spec["home"]["endpoint"]).map(|at| format!(", endpoint {at}"));
        let held = resource.status.as_ref().map(|status| &status["home"]);
        let held = match held.and_then(|home| Some((said(&home["holder"])?, said(&home["since"])?))) {
            Some((holder, since)) => format!(", held by {holder} since {since}"),
            None => ", held by no one yet".to_string(),
        };
        return format!("house {}{}{held}", clean(address), endpoint.unwrap_or_default());
    }
    let Some(status) = &resource.status else {
        return String::new();
    };
    match (status["ready"].as_u64(), status["replicas"].as_u64()) {
        (Some(ready), Some(replicas)) => {
            // Why it is not ready, if a container said so.
            let containers = status["containers"].as_array().into_iter().flatten();
            let containers: Vec<_> = containers.collect();
            // A pull that goes on is the news; a message beside it is from before.
            let why = containers.iter().find_map(|c| pull_text(&c["pull"]));
            let why = why.or_else(|| containers.iter().find_map(|c| c["message"].as_str()).map(clean));
            let why = why.map(|m| format!(": {m}")).unwrap_or_default();
            format!("{ready}/{replicas} ready{why}")
        }
        // A Job or a DNS record; a Node: its state and where it is.
        _ => match (
            status["state"].as_str(),
            status["message"].as_str(),
            status["address"].as_str(),
        ) {
            (Some(state), Some(why), _) if state != "succeeded" => format!("{state}: {}", clean(why)),
            // A Node: its address, which is its LAN address unless it roams (then a mesh address), and what it serves.
            (Some(state), _, Some(address)) if resource.kind == "Node" => {
                // (A node the leader has moved onto the mesh keeps its LAN address in `status.lan`.)
                let mesh = if resource.spec["roaming"] == true || status["lan"].is_string() {
                    " (mesh)"
                } else {
                    ""
                };
                let serves = serves_summary(status);
                format!("{state} at {}{mesh}{serves}", clean(address))
            }
            (Some(state), _, Some(address)) => format!("{state} at {}", clean(address)),
            (Some(state), ..) | (None, _, Some(state)) => clean(state),
            _ => String::new(),
        },
    }
}

/// What a Node says it serves (`status.serves`), for its STATUS: `; serves dns 53, ingress`, or nothing.
fn serves_summary(status: &serde_json::Value) -> String {
    let serves = &status["serves"];
    let mut said = Vec::new();
    if let Some(port) = serves["dns"].as_u64() {
        said.push(format!("dns {port}"));
    }
    if serves["ingress"] == true {
        said.push("ingress".to_string());
    }
    if said.is_empty() {
        String::new()
    } else {
        format!("; serves {}", said.join(", "))
    }
}

/// A kind as a command needs it: one of kith's own, or one a KindDefinition in the
/// cluster makes.
struct Kind {
    kind: String,
    namespaced: bool,
    /// The columns `kith get` shows for it (name, dotted path), when it says.
    columns: Vec<(String, String)>,
    /// The schema of its spec (a made kind's only: kith's own have a whole one).
    schema: serde_json::Value,
}

impl Kind {
    /// The kind called `name`, in any case; the cluster is asked only when it is not kith's own.
    fn find(name: &str, backend: &dyn Fn() -> Result<Backend, String>) -> Result<Kind, String> {
        if let Some(own) = kith_api::kind(name) {
            return Ok(Kind {
                kind: own.kind.into(),
                namespaced: own.namespaced,
                columns: Vec::new(),
                schema: serde_json::Value::Null,
            });
        }
        let unknown = |why: &str| {
            fail(format!(
                "error: unknown kind `{name}` (`kith schema` lists the kinds{why})"
            ))
        };
        let defined = match backend().and_then(|backend| backend.list(Some("KindDefinition"))) {
            Ok(defined) => defined,
            Err(e) => return unknown(&format!("; the cluster's own could not be asked for: {e}")),
        };
        let made = |d: &&Resource| {
            d.spec["kind"]
                .as_str()
                .is_some_and(|kind| kind.eq_ignore_ascii_case(name))
        };
        let Some(definition) = defined.iter().find(made) else {
            return unknown("");
        };
        let columns = definition.spec["columns"].as_array().into_iter().flatten();
        let text = |value: &serde_json::Value| value.as_str().unwrap_or_default().replace(char::is_control, "");
        Ok(Kind {
            kind: text(&definition.spec["kind"]),
            namespaced: definition.spec["namespaced"] != false,
            columns: columns
                .map(|column| (text(&column["name"]), text(&column["path"])))
                .collect(),
            schema: definition.spec["schema"].clone(),
        })
    }

    fn key(&self, name: &str, namespace: Option<&str>) -> String {
        match self.namespaced {
            true => format!("{}/{}/{name}", self.kind, namespace.unwrap_or(DEFAULT_NAMESPACE)),
            false => format!("{}/{name}", self.kind),
        }
    }
}

impl Target {
    fn key(&self, backend: &dyn Fn() -> Result<Backend, String>) -> Result<String, String> {
        let (kind, name) = match (self.target.split_once('/'), &self.name) {
            (Some((kind, name)), None) => (kind, name),
            (None, Some(name)) => (self.target.as_str(), name.as_str()),
            _ => return fail("name the resource as KIND/NAME or KIND NAME"),
        };
        Ok(Kind::find(kind, backend)?.key(name, self.namespace.as_deref()))
    }
}

/// What a file in kith's own language gives (README: kith's own language), or all that
/// is wrong with it, each with its place. `listed`: it is one of a directory, where a
/// file that is only there to be imported gives nothing and is no mistake.
fn lang(path: &Path, listed: bool) -> Result<Vec<Resource>, Vec<String>> {
    // (Imports are of files beside it: its directory is all it can read.)
    let dir = path.parent().filter(|dir| !dir.as_os_str().is_empty());
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let beside = kith_lang::dir(dir.unwrap_or(Path::new(".")));
    // (The file that was named may be a link, as a YAML file may: what it imports may not.)
    let named = std::fs::read_to_string(path).map_err(|e| e.to_string());
    let read = |file: &str| if file == name { named.clone() } else { beside(file) };
    let found = match listed {
        true => kith_lang::resources_if_any(&name, &read, &[]),
        false => kith_lang::resources(&name, &read, &[]),
    };
    // (A place is said by the file's name in that directory: here, by its path.)
    let shown = |wrong: kith_lang::Error| match (&wrong.at, dir) {
        (Some(_), Some(dir)) => format!("{}/{wrong}", dir.display()),
        (Some(_), None) => wrong.to_string(),
        (None, _) => format!("{}: {wrong}", path.display()),
    };
    found.map_err(|wrong| wrong.into_iter().map(shown).collect())
}

/// Read and validate every document in the given files. All problems are
/// reported at once, each as `file:line:column: message`.
fn load(files: &Files) -> Result<Vec<Resource>, String> {
    let mut paths = Vec::new();
    for path in &files.files {
        if path.is_dir() {
            let entries = std::fs::read_dir(path).or_else(|e| fail(format!("{}: {e}", path.display())))?;
            let mut found: Vec<PathBuf> = entries
                .filter_map(|e| Some(e.ok()?.path()))
                .filter(|p| {
                    matches!(
                        p.extension().and_then(|e| e.to_str()),
                        Some("yaml" | "yml" | "json" | "kith")
                    )
                })
                .collect();
            found.sort();
            paths.extend(found.into_iter().map(|found| (found, true)));
        } else {
            paths.push((path.clone(), false));
        }
    }
    let (mut resources, mut errors) = (Vec::new(), Vec::new());
    for (path, listed) in paths {
        if path.extension().is_some_and(|extension| extension == "kith") {
            match lang(&path, listed) {
                Ok(found) => resources.extend(found),
                Err(wrong) => errors.extend(wrong),
            }
            continue;
        }
        let (name, src) = if path.as_os_str() == "-" {
            STDIN_WAS_INPUT.store(true, std::sync::atomic::Ordering::SeqCst);
            let mut src = String::new();
            std::io::stdin()
                .read_to_string(&mut src)
                .or_else(|e| fail(format!("stdin: {e}")))?;
            ("<stdin>".to_string(), src)
        } else {
            let src = std::fs::read_to_string(&path).or_else(|e| fail(format!("{}: {e}", path.display())))?;
            (path.display().to_string(), src)
        };
        match Resource::from_source(&src) {
            Err(e) => errors.push(e.render(&name, &src)),
            Ok(docs) => {
                for doc in docs {
                    match doc {
                        Ok(resource) => resources.push(resource),
                        Err(e) => errors.push(e.render(&name, &src)),
                    }
                }
            }
        }
    }
    if errors.is_empty() {
        for resource in &resources {
            for field in resource.not_acted_on() {
                let key = resource.key();
                eprintln!("note: {key}: spec.{field} is kept and not acted on (nothing in kith reads it)");
            }
        }
        Ok(resources)
    } else {
        Err(errors.join("\n"))
    }
}

/// Print a unit's output from kithd's `path` (`kith logs`, and `kith launch` following its Job):
/// from `tail` lines back or the start; with `follow`, until no more may come. False when stdout
/// was closed first (`kith logs | head`). It is written to `out`.
fn stream_logs(
    kithd: &Kithd,
    path: &str,
    tail: Option<u64>,
    follow: bool,
    out: &mut dyn std::io::Write,
) -> Result<bool, String> {
    let mut from = tail.map_or("&offset=0".into(), |lines| format!("&tail={lines}"));
    loop {
        let reply: serde_json::Value = request(kithd, "GET", &format!("{path}{from}"), b"")?;
        let data = reply["data"].as_str().unwrap_or_default();
        if out.write_all(data.as_bytes()).and_then(|()| out.flush()).is_err() {
            return Ok(false);
        }
        from = format!("&offset={}", reply["next"].as_u64().unwrap_or(0));
        if data.is_empty() {
            // Drained. Without -f that is all; with it, wait for more while more may come.
            if !follow || reply["more"] != true {
                return Ok(true);
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }
}

fn print_table<const N: usize>(header: [&str; N], rows: Vec<[String; N]>) {
    print_rows(&header, &rows.into_iter().map(Vec::from).collect::<Vec<_>>());
}

fn print_rows(header: &[&str], rows: &[Vec<String>]) {
    let mut widths: Vec<usize> = header.iter().map(|title| title.chars().count()).collect();
    for row in rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.chars().count());
        }
    }
    let line = |cells: Vec<&str>| {
        let cols: Vec<String> = cells.iter().zip(&widths).map(|(c, w)| format!("{c:<w$}")).collect();
        println!("{}", cols.join("  ").trim_end());
    };
    line(header.to_vec());
    for row in rows {
        line(row.iter().map(String::as_str).collect());
    }
}

/// The `--spec` file of the features NAME's hardware wants (`status.os.wants`, from its PCI cards
/// matched by os/features' `# pci:` ids), for os/build.sh. A name that is not a feature name is
/// refused: os/build.sh reads the list as names, so a comma in one would add a feature.
fn features_spec(node: &Resource) -> Result<String, String> {
    let name = &node.metadata.name;
    let wants = node
        .status
        .as_ref()
        .and_then(|status| status["os"]["wants"].as_array())
        .ok_or_else(|| {
            format!("{name} has not said what its hardware wants: it runs no kith OS, or its kithd is older")
        })?;
    let names = wants
        .iter()
        .map(|want| {
            want.as_str()
                .filter(|want| {
                    !want.is_empty()
                        && want
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                })
                .ok_or_else(|| format!("{name}'s wants are not feature names"))
        })
        .collect::<Result<Vec<&str>, String>>()?;
    let mut text = if names.is_empty() {
        format!("# {name}: no feature matches its PCI cards, so none is wanted\n")
    } else {
        format!("# {name}: the features its hardware wants, from its PCI cards (os/features' # pci: ids)\n")
    };
    text.push_str(&format!("features: [{}]\n", names.join(", ")));
    Ok(text)
}

/// What `kith node encrypt` says of the node's answer: its recovery key, shown once, and what
/// happens next; or that an encryption not yet started was taken away.
fn encrypt_text(name: &str, cancel: bool, said: &serde_json::Value) -> Result<String, String> {
    if cancel {
        return Ok(format!(
            "{name}'s encryption is cancelled: nothing was encrypted, and its state is as it was.\n"
        ));
    }
    let key = said["recovery"].as_str().ok_or(format!(
        "No recovery key was shown. If {name} marked its state before this failed, `kith node encrypt {name} --cancel` takes the mark away until it starts."
    ))?;
    Ok(format!(
        "{name}'s recovery key, shown this once and kept nowhere: write it down. {name} restarts now and encrypts its state as it starts, which takes a while: it is down until that is done. Typed at {name}'s console when it starts and no node hands its key out, the key opens its state. `kith node encrypt {name} --cancel` takes the encryption away only until it starts. On flash, old plain blocks may survive: see the cluster guide.\n\n    {key}\n"
    ))
}

#[cfg(test)]
mod node_encrypt_tests {
    use super::{Cli, Command, NodeCommand, encrypt_text};
    use clap::Parser;
    use serde_json::json;

    #[test]
    fn node_encrypt_takes_a_name_and_cancel_and_nothing_else() {
        let parsed = |args: &[&str]| match Cli::try_parse_from(args).map(|cli| cli.command) {
            Ok(Command::Node {
                command: NodeCommand::Encrypt { name, cancel },
            }) => Some((name, cancel)),
            _ => None,
        };
        assert_eq!(parsed(&["kith", "node", "encrypt", "n1"]), Some(("n1".into(), false)));
        assert_eq!(
            parsed(&["kith", "node", "encrypt", "n1", "--cancel"]),
            Some(("n1".into(), true))
        );
        assert_eq!(parsed(&["kith", "node", "encrypt"]), None);
        assert_eq!(parsed(&["kith", "node", "encrypt", "n1", "--now"]), None);
    }

    #[test]
    fn node_encrypt_shows_the_recovery_key_once_and_says_what_next() {
        let key = "0123 4567 89ab cdef 0123 4567 89ab cdef";
        let text = encrypt_text("n1", false, &json!({ "node": "n1", "recovery": key })).unwrap();
        assert_eq!(text.matches(key).count(), 1, "{text}");
        assert!(text.contains("restarts") && text.contains("--cancel"), "{text}");
        assert!(text.contains("On flash, old plain blocks may survive"), "{text}");
        assert!(encrypt_text("n1", false, &json!({ "node": "n1" })).is_err());
    }

    #[test]
    fn node_encrypt_cancel_says_so_and_shows_no_key() {
        let text = encrypt_text("n1", true, &json!({ "node": "n1", "cancelled": true })).unwrap();
        assert!(text.contains("cancelled") && !text.contains("recovery"), "{text}");
    }
}

#[cfg(test)]
mod passphrase_tests {
    use super::{Source, passphrase_source};

    #[test]
    fn the_admin_passphrase_comes_from_the_terminal_or_one_stdin_line_never_a_manifest() {
        assert_eq!(passphrase_source(true, false), Source::Tty);
        assert_eq!(passphrase_source(true, true), Source::Tty);
        assert_eq!(passphrase_source(false, false), Source::Stdin);
        assert_eq!(passphrase_source(false, true), Source::Refuse);
    }

    #[test]
    fn a_read_another_node_may_pass_on_is_signed_and_the_rest_are_not() {
        // (The list is kith-api's, shared with kithd: its own test checks each route.)
        assert!(kith_api::passed_on("GET", "/v1/logs/Workload/default/web?replica=0"));
        assert!(kith_api::passed_on("GET", "/v1/volumes/default/data/files"));
        assert!(!kith_api::passed_on("GET", "/v1/cluster"));
        assert!(!kith_api::passed_on("GET", "/v1/resources?namespace=default"));
    }

    #[test]
    fn a_streamed_put_is_refused_where_writes_must_be_signed_and_says_why() {
        use super::streamed_refusal;
        let why = streamed_refusal(&serde_json::json!({"signing": "required"})).unwrap();
        assert!(
            why.contains("as a stream") && why.contains("spec.signing: required"),
            "{why}"
        );
        assert!(streamed_refusal(&serde_json::json!({"signing": "open"})).is_none());
    }
}

#[cfg(test)]
mod peer_tests {
    use super::{Cli, peer_text};
    use clap::Parser;
    use serde_json::json;

    #[test]
    fn peer_add_asks_for_a_name_a_node_and_a_level() {
        let cli = Cli::try_parse_from(["kith", "peer", "add", "phone", "--node", "n1", "--level", "family"]);
        assert!(cli.is_ok());
        assert!(Cli::try_parse_from(["kith", "peer", "add", "phone", "--node", "n1"]).is_err());
        assert!(Cli::try_parse_from(["kith", "peer", "add", "--node", "n1", "--level", "family"]).is_err());
    }

    #[test]
    fn peer_add_replace_is_a_flag_and_off_unless_given() {
        use super::{Command, PeerCommand};
        let replace_of = |args: &[&str]| match Cli::try_parse_from(args).unwrap().command {
            Command::Peer {
                command: PeerCommand::Add { replace, .. },
            } => replace,
            _ => panic!("not peer add"),
        };
        let base = ["kith", "peer", "add", "phone", "--node", "n1", "--level", "family"];
        assert!(!replace_of(&base));
        assert!(replace_of(&[&base[..], &["--replace"]].concat()));
    }

    #[test]
    fn peer_add_prints_the_configuration_and_says_it_is_shown_once() {
        let answer = json!({
            "name": "phone", "node": "n1", "level": "family",
            "publicKey": "cHVibGlj",
            "addresses": {"ipv4": "100.89.0.2", "ipv6": "fd00::2"},
            "config": "[Interface]\nPrivateKey = c2VjcmV0\nAddress = 100.89.0.2/32\n\n[Peer]\nPublicKey = bm9kZQ==\n",
        });
        let text = peer_text(&answer).unwrap();
        assert!(text.contains("shown this once"), "{text}");
        assert!(text.contains("kept nowhere"), "{text}");
        assert!(text.contains("whoever has it is this peer"), "{text}");
        assert!(text.contains("[Interface]\nPrivateKey = c2VjcmV0\n"), "{text}");
        assert!(text.contains("phone"), "{text}");
        // An answer with no configuration is no answer: nothing is printed as one.
        assert!(peer_text(&json!({"name": "phone"})).is_err());
    }
}

#[cfg(test)]
mod drain_tests {
    use super::drain_text;
    use serde_json::json;

    #[test]
    fn pull_progress_shows_in_the_status_column_while_an_image_is_pulled() {
        use kith_api::Resource;
        let workload = |status: serde_json::Value| {
            let workload = json!({
                "apiVersion": "kith.dev/v1", "kind": "Workload", "metadata": { "name": "web" },
                "spec": {}, "status": status,
            });
            super::status_summary(&serde_json::from_value::<Resource>(workload).unwrap())
        };
        let pull = json!({ "layers": 3, "layersTotal": 7, "bytes": 12_000_000, "bytesTotal": 40_000_000 });
        let pulling = workload(json!({ "ready": 0, "replicas": 1, "containers": [
            { "name": "web", "message": "pending", "pull": pull },
        ]}));
        assert_eq!(pulling, "0/1 ready: pulling 3 of 7 layers, 12 of 40 MB");
        // Small images count in KB; a container that does not pull says what it said.
        let small = json!({ "layers": 0, "layersTotal": 1, "bytes": 0, "bytesTotal": 4_500 });
        let said = workload(json!({ "ready": 0, "replicas": 1, "containers": [
            { "name": "a", "message": "stopped" }, { "name": "b", "pull": small },
        ]}));
        assert_eq!(said, "0/1 ready: pulling 0 of 1 layers, 0.0 of 4.5 KB");
        let plain =
            workload(json!({ "ready": 0, "replicas": 1, "containers": [{ "name": "a", "message": "stopped" }] }));
        assert_eq!(plain, "0/1 ready: stopped");
        assert_eq!(
            workload(json!({ "ready": 1, "replicas": 1, "containers": [{ "name": "a" }] })),
            "1/1 ready"
        );
    }

    #[test]
    fn drain_says_what_moves_stays_and_what_is_lost_before_anything_changes() {
        let plan = [
            json!({"key": "Workload/web", "replica": "0", "outcome": "moves", "to": "b", "why": "",
                   "if_lost": "moves to another node once the node is lost, if one can take it"}),
            json!({"key": "Job/default/train", "replica": "0", "outcome": "stays", "to": null,
                   "why": "running here: a drain leaves it to finish",
                   "if_lost": "starts over on another node once the node is lost, if one can take it"}),
            json!({"key": "Workload/data", "replica": "0", "outcome": "stays", "to": null,
                   "why": "no other node can take it: 0/2 nodes can take it: 1 cordoned, 1 not enough cpu",
                   "if_lost": "moves to another node once the node is lost, if one can take it"}),
            json!({"key": "NodeWorkload/agent", "replica": null, "outcome": "removed", "to": null,
                   "why": "another NoExecute taint is on the node", "if_lost": "its copy comes back when the node does"}),
        ];
        let text = drain_text("a", &plan);
        assert_eq!(text.len(), 4, "{text:?}");
        assert_eq!(text[0], "  Workload/web#0 moves to b", "{text:?}");
        assert!(
            text[1].contains("Job/default/train#0 stays on a: running here"),
            "{text:?}"
        );
        // The last node that can run it: the drain keeps it, and says why.
        assert!(text[2].contains("stays on a: no other node can take it"), "{text:?}");
        assert!(text[3].starts_with("  NodeWorkload/agent comes off a:"), "{text:?}");
        assert_eq!(drain_text("a", &[]), ["nothing runs on a: nothing moves"]);
    }

    #[test]
    fn nodes_say_their_lan_address_or_that_they_are_on_the_mesh_and_what_they_serve() {
        use crate::table_row;
        use kith_api::Resource;
        let node = |spec: serde_json::Value, status: serde_json::Value| {
            let node = json!({
                "apiVersion": "kith.dev/v1", "kind": "Node", "metadata": { "name": "n" },
                "spec": spec, "status": status,
            });
            serde_json::from_value::<Resource>(node).unwrap()
        };
        let lan = node(
            json!({}),
            json!({ "address": "192.0.2.7:7443", "state": "ready", "serves": { "dns": 53, "ingress": true } }),
        );
        assert_eq!(lan.lan_address().map(|ip| ip.to_string()).as_deref(), Some("192.0.2.7"));
        assert_eq!(table_row(&lan)[4], "ready at 192.0.2.7:7443; serves dns 53, ingress");
        // Moved onto the mesh by the leader: its LAN address is the one it was moved from.
        let moved = node(
            json!({}),
            json!({ "address": "[fd00::7]:7443", "lan": "192.0.2.7:7443", "state": "ready" }),
        );
        assert_eq!(
            moved.lan_address().map(|ip| ip.to_string()).as_deref(),
            Some("192.0.2.7")
        );
        assert_eq!(table_row(&moved)[4], "ready at [fd00::7]:7443 (mesh)");
        let roaming = node(
            json!({ "roaming": true }),
            json!({ "address": "10.8.0.4:7443", "state": "ready" }),
        );
        assert!(roaming.lan_address().is_none());
        assert_eq!(table_row(&roaming)[4], "ready at 10.8.0.4:7443 (mesh)");
        let plain = node(
            json!({}),
            json!({ "address": "198.51.100.9:7443", "state": "ready", "serves": {} }),
        );
        assert_eq!(table_row(&plain)[4], "ready at 198.51.100.9:7443");
    }

    #[test]
    fn get_cluster_home_says_the_house_address_endpoint_holder_and_since() {
        use crate::table_row;
        use kith_api::Resource;
        let cluster = |spec: serde_json::Value, status: Option<serde_json::Value>| {
            let mut cluster = json!({ "apiVersion": "kith.dev/v1", "kind": "Cluster", "metadata": { "name": "house" }, "spec": spec });
            cluster["status"] = status.unwrap_or(serde_json::Value::Null);
            serde_json::from_value::<Resource>(cluster).unwrap()
        };
        let home = json!({ "home": { "address": "192.168.1.250/24", "endpoint": "house.example.org:51820" } });
        let held = json!({ "home": { "holder": "n1", "since": "2026-11-18T09:00:00Z" } });
        assert_eq!(
            table_row(&cluster(home.clone(), Some(held)))[4],
            "house 192.168.1.250/24, endpoint house.example.org:51820, held by n1 since 2026-11-18T09:00:00Z"
        );
        // Not held yet, and no endpoint: it says so, and no more.
        let bare = json!({ "home": { "address": "192.168.1.250/24" } });
        assert_eq!(
            table_row(&cluster(bare, None))[4],
            "house 192.168.1.250/24, held by no one yet"
        );
        // A Cluster with no house says nothing here.
        assert_eq!(table_row(&cluster(json!({}), None))[4], "");
        // What a node writes there cannot drive the terminal.
        let held = json!({ "home": { "holder": "n\u{1b}[2J", "since": "now" } });
        assert!(!table_row(&cluster(home, Some(held)))[4].contains('\u{1b}'));
    }

    #[test]
    fn features_spec_writes_all_for_a_node_that_wants_all() {
        use super::features_spec;
        use kith_api::Resource;
        let node = json!({
            "apiVersion": "kith.dev/v1", "kind": "Node", "metadata": { "name": "gtx" },
            "spec": {}, "status": { "os": { "wants": ["all"] } },
        });
        let spec = features_spec(&serde_json::from_value::<Resource>(node).unwrap()).unwrap();
        assert!(spec.ends_with("features: [all]\n"), "{spec}");
    }

    #[test]
    fn node_features_prints_the_spec_the_node_wants() {
        use super::features_spec;
        use kith_api::Resource;
        let node = |status: serde_json::Value| {
            let node = json!({
                "apiVersion": "kith.dev/v1", "kind": "Node", "metadata": { "name": "n1" },
                "spec": {}, "status": status,
            });
            serde_json::from_value::<Resource>(node).unwrap()
        };
        let spec = features_spec(&node(json!({ "os": { "wants": ["gpu-amd-phoenix", "nic-x"] } }))).unwrap();
        assert_eq!(
            spec,
            "# n1: the features its hardware wants, from its PCI cards (os/features' # pci: ids)\nfeatures: [gpu-amd-phoenix, nic-x]\n"
        );
        let none = features_spec(&node(json!({ "os": { "wants": [] } }))).unwrap();
        assert!(none.contains("# n1: no feature matches its PCI cards"), "{none}");
        assert!(none.ends_with("features: []\n"), "{none}");
        // Not a kith OS node (no status.os.wants at all): said, not an empty spec.
        assert!(features_spec(&node(json!({ "state": "ready" }))).is_err());
        // A name that is not a feature name is refused, so none can add a feature to the spec.
        assert!(features_spec(&node(json!({ "os": { "wants": ["a, gpu"] } }))).is_err());
    }

    #[test]
    fn scan_said_has_a_row_for_each_id_with_its_link_and_prints_nothing_a_node_sent_raw() {
        let said = json!({
            "node": "alpha", "image": "debian:12", "ecosystem": "Debian:12", "packages": 90,
            "vulnerable": [
                { "name": "openssl", "version": "3.0.11-1", "ids": ["CVE-2023-5678", "DSA-5532-1"] },
                { "name": "ba\u{1b}sh", "version": "5.2", "ids": ["CVE-1"] },
            ],
        });
        let out = super::scan_said(&said);
        let lines: Vec<_> = out.lines().collect();
        assert_eq!(
            lines[0],
            "debian:12 on alpha: 90 packages (Debian:12), 2 with advisories in OSV"
        );
        assert!(
            lines[1].starts_with("PACKAGE") && lines[1].ends_with("ADVISORY"),
            "{out}"
        );
        assert!(
            lines[2].ends_with("CVE-2023-5678  https://osv.dev/vulnerability/CVE-2023-5678"),
            "{out}"
        );
        // (A package's name and version come once, on its first row.)
        assert!(
            lines[3].starts_with(' ') && lines[3].ends_with("https://osv.dev/vulnerability/DSA-5532-1"),
            "{out}"
        );
        assert!(lines[4].starts_with("ba?sh"), "{out}");
        assert!(!out.contains('\u{1b}'));
        // Nothing found: the header alone.
        let clean = super::scan_said(
            &json!({ "node": "a", "image": "i", "ecosystem": "Alpine:v3.19", "packages": 3, "vulnerable": [] }),
        );
        assert_eq!(clean, "i on a: 3 packages (Alpine:v3.19), 0 with advisories in OSV\n");
    }
}
