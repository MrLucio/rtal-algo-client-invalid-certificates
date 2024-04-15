use auth::get_valid_credentials;
use clap::{ArgEnum, Parser, Subcommand};
use futures_util::sink::Sink;
use futures_util::stream::Stream;
use futures_util::{SinkExt, StreamExt};
use regex::Regex;
use rtal::auth;
use rtal::proto;
use rtal::proto::{Reply, Request};
use rtal::util::send_binary_data;
use rtal::util::{oneshot_reply, oneshot_request, recv_binary_data};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::error::Error;
use std::fmt::Display;
use std::path::PathBuf;
use std::process::Stdio;
use std::str::FromStr;
use tokio::io::{stdin, stdout, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process as proc;
use tokio::runtime::Runtime;
use tokio::select;
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::tungstenite::Error as TsError;
use tokio_tungstenite::{connect_async, MaybeTlsStream};
use tracing::{error, warn};

const BUFFER_SIZE: usize = 1 << 16;

fn parse_key_val<T, U>(s: &str) -> Result<(T, U), Box<dyn Error + Send + Sync + 'static>>
where
    T: FromStr,
    T::Err: Error + Send + Sync + 'static,
    U: FromStr,
    U::Err: Error + Send + Sync + 'static,
{
    let pos = s
        .find('=')
        .ok_or_else(|| format!("invalid KEY=value: no `=` found in `{}`", s))?;
    Ok((s[..pos].parse()?, s[pos + 1..].parse()?))
}

fn parse_key_val_optional<T, U>(s: &str) -> Result<(T, U), Box<dyn Error + Send + Sync + 'static>>
where
    T: FromStr,
    T::Err: Error + Send + Sync + 'static,
    U: FromStr,
    U::Err: Error + Send + Sync + 'static,
{
    if let Some(pos) = s.find('=') {
        Ok((s[..pos].parse()?, s[pos + 1..].parse()?))
    } else {
        Ok((s.parse()?, "1".parse()?))
    }
}

#[derive(Parser, Debug, Clone)]
#[clap(version)]
struct CliArgs {
    #[clap(
        short,
        long,
        help = "Server URL",
        default_value = "ws://127.0.0.1:8008/"
    )]
    server_url: String,
    #[clap(subcommand)]
    command: Command,
}

#[derive(ArgEnum, Debug, Clone, PartialEq, Eq)]
enum CommunicationChannel {
    Stdio,
    #[cfg(unix)]
    Pipe,
}

#[derive(ArgEnum, Debug, Clone, PartialEq, Eq)]
enum Color {
    Auto,
    On,
    Off,
}

#[derive(Subcommand, Debug, Clone)]
enum Command {
    /// List available problems
    List {
        #[clap(help = "Filter problems with a regex")]
        filter: Option<Regex>,
        #[clap(
            short,
            long,
            parse(from_occurrences),
            help = "List services and parameters, add more than one to list more information"
        )]
        verbose: u8,
    },
    /// Download problem attachments
    Get {
        #[clap(help = "Name of the problem to download the attachments")]
        problem: String,
        #[clap(
            short,
            long,
            help = "Path to output the attachments [default: <problem_name>.tar]"
        )]
        output: Option<String>,
    },
    /// Connect to problem evaluator
    Connect {
        #[clap(short, long, help = "Echo messages on console")]
        echo: bool,
        #[clap(
            arg_enum,
            short = 'k',
            long,
            help = "Disable colored output",
            default_value = "auto"
        )]
        color: Color,
        #[clap(short = 'x', long, help = "Authentication token")]
        auth_token: Option<String>,
        #[clap(
            long,
            help = "Credentials file to create, defaults to app data directory location"
        )]
        cred_file: Option<PathBuf>,
        #[clap(
            arg_enum,
            short,
            long,
            help = "Channel for program communication",
            default_value = "stdio"
        )]
        channel: CommunicationChannel,
        #[clap(help = "Remote problem to connect to")]
        problem: String,
        #[clap(help = "Service wanted", default_value = "solve")]
        service: String,
        #[clap(short = 'a', long, multiple_occurrences(true), parse(try_from_str = parse_key_val_optional), help = "Service arguments, can be specified multiple times with -a arg=val")]
        service_arg: Vec<(String, String)>,
        #[clap(short = 'f', long, multiple_occurrences(true), parse(try_from_str = parse_key_val), help = "File arguments, can be specified multiple times with -f arg=file")]
        file_arg: Vec<(String, String)>,
        #[clap(
            short,
            long,
            help = "Path to output the attachments",
            default_value = "./output/"
        )]
        output: PathBuf,
        #[clap(help = "Local executable and executable arguments", raw = true)]
        program: Vec<String>,
    },
    Login {
        #[clap(
            short,
            long,
            help = "Credentials file to create, defaults to app data directory location"
        )]
        cred_file: Option<PathBuf>,
    },
    Logout {
        #[clap(
            short,
            long,
            help = "Credentials file to create, defaults to app data directory location"
        )]
        cred_file: Option<PathBuf>,
    },
}

impl Command {
    async fn run<T: Sink<Message> + Unpin, U: Stream<Item = Result<Message, TsError>> + Unpin>(
        self,
        uri: &str,
        wsout: &mut T,
        wsin: &mut U,
        ask_to_exit: &mut bool,
    ) -> Result<(), String>
    where
        <T as Sink<Message>>::Error: Display,
    {
        match self {
            Command::List {
                filter,
                mut verbose,
            } => {
                let request = Request::MetaList {};
                let reply = match oneshot_request(request, wsout, wsin).await? {
                    Reply::MetaList { meta } => meta,
                    _ => return Err(format!("Server sent an invalid response")),
                };
                verbose += if filter.is_some() { 1 } else { 0 };
                let meta: BTreeMap<_, _> = reply.into_iter().collect();
                for (name, meta) in meta.into_iter() {
                    if let Some(filter) = &filter {
                        if !filter.is_match(&name) {
                            continue;
                        }
                    }
                    println!("- {}", name);
                    if verbose >= 1 {
                        let services: BTreeMap<_, _> = meta.services.into_iter().collect();
                        for (servname, servargs) in services.into_iter() {
                            println!("  * {}", servname);
                            if let Some(args) = servargs.args {
                                let args: BTreeMap<_, _> = args.into_iter().collect();
                                for (argname, arg) in args.into_iter() {
                                    if verbose >= 2 {
                                        if let Some(def) = arg.default {
                                            println!("    # {} [{}] {}", argname, def, arg.regex);
                                        } else {
                                            println!("    # {} {}", argname, arg.regex);
                                        }
                                    } else {
                                        if let Some(def) = arg.default {
                                            println!("    # {} [{}]", argname, def);
                                        } else {
                                            println!("    # {}", argname);
                                        }
                                    }
                                }
                            }
                            if let Some(mut args) = servargs.files {
                                args.sort();
                                for arg in args.into_iter() {
                                    println!("    § {}", arg);
                                }
                            }
                        }
                    }
                }
                Ok(())
            }
            Command::Get { problem, output } => {
                let request = Request::Attachment { problem };
                match oneshot_request(request, wsout, wsin).await? {
                    Reply::Attachment { status: Ok(()) } => {}
                    Reply::Attachment { status: Err(x) } => {
                        return Err(format!("Cannot download attachment: {}", x))
                    }
                    _ => return Err(format!("Server sent an invalid response")),
                };
                let (name, data) = match recv_binary_data(wsin).await {
                    Ok(x) => x,
                    Err(x) => return Err(format!("Error while downloading the attachment: {}", x)),
                };
                let name = output.unwrap_or(name);
                tokio::fs::write(name, data)
                    .await
                    .map_err(|x| format!("Error while writing attachment to disk: {}", x))
            }
            Command::Connect {
                echo,
                color,
                auth_token,
                cred_file,
                channel,
                problem,
                service,
                service_arg,
                file_arg,
                output,
                program,
            } => {
                let request = Request::ConnectBegin {
                    problem,
                    service,
                    args: service_arg.into_iter().collect(),
                    tty: match color {
                        Color::Auto => program.len() == 0 && channel == CommunicationChannel::Stdio,
                        Color::Off => false,
                        Color::On => true,
                    },
                    token: {
                        let auth_file = match cred_file {
                            Some(x) => x,
                            None => auth::resolve_login_file(None)?,
                        };
                        let login_data = auth::load_credentials(&auth_file);
                        if let Ok(creds) = login_data {
                            Some(creds.1)
                        } else {
                            auth_token
                        }
                    },
                    files: file_arg.iter().map(|x| x.0.clone()).collect(),
                };
                let allowed_files = match oneshot_request(request, wsout, wsin).await? {
                    Reply::ConnectBegin { status: Ok(x) } => x,
                    Reply::ConnectBegin { status: Err(x) } => {
                        return Err(format!("Cannot connect: {}", x))
                    }
                    _ => return Err(format!("Server sent an invalid response")),
                };
                let provided_files: HashMap<_, _> = file_arg.into_iter().collect();
                let allowed_files: HashSet<_> = allowed_files.into_iter().collect();
                let mut to_upload = Vec::new();
                for (name, path) in provided_files {
                    if !allowed_files.contains(&name) {
                        return Err(format!("File \"{}\" is not allowed", &name));
                    }
                    match tokio::fs::read(&path).await {
                        Ok(x) => to_upload.push((name, x)),
                        Err(x) => return Err(format!("Cannot read {}: {}", path, x)),
                    }
                }
                for (name, data) in to_upload {
                    if let Err(x) = send_binary_data(wsout, &name, &data).await {
                        return Err(format!("Cannot send input file: {}", x));
                    }
                }
                match oneshot_reply(wsin).await? {
                    Reply::ConnectStart { status: Ok(()) } => {}
                    Reply::ConnectStart { status: Err(x) } => {
                        return Err(format!("Cannot start connection: {}", x))
                    }
                    _ => return Err(format!("Server sent an invalid response")),
                };
                // BEGIN: Handle channels
                let output_files = match channel {
                    CommunicationChannel::Stdio => {
                        if program.len() > 0 {
                            loop {
                                let mut prog = proc::Command::new(&program[0]);
                                if program.len() > 1 {
                                    prog.args(&program[1..]);
                                }
                                prog.stdout(Stdio::piped());
                                prog.stdin(Stdio::piped());
                                let mut prog = match prog.spawn() {
                                    Ok(x) => x,
                                    Err(x) => return Err(format!("Cannot spawn program: {}", x)),
                                };
                                let result = handle_connection(
                                    wsout,
                                    wsin,
                                    prog.stdout.take().expect("Cannot fail"),
                                    prog.stdin.take().expect("Cannot fail"),
                                    echo,
                                )
                                .await;

                                match result {
                                    Ok(y) => {
                                        match prog.try_wait() {
                                            Ok(Some(x)) if x.success() => {}
                                            Ok(Some(x)) => {
                                                warn!("Program exited with non-zero code: {}", x);
                                            }
                                            Ok(None) => {
                                                warn!("Received new subtask, restarting user program...");
                                                let _ = prog.kill();
                                            }
                                            Err(x) => {
                                                warn!("Program exited abruptly: {}", x);
                                                let _ = prog.kill();
                                            }
                                        };

                                        match y {
                                            RunResult::Restart => {
                                                continue;
                                            }
                                            RunResult::Terminate { status } => break Ok(status),
                                        }
                                    }
                                    Err(x) => {
                                        drop(prog.kill().await);
                                        break Err(x);
                                    }
                                }
                            }
                        } else {
                            let result = loop {
                                match handle_connection(wsout, wsin, stdin(), stdout(), false).await
                                {
                                    Ok(res) => match res {
                                        RunResult::Restart => continue,
                                        RunResult::Terminate { status } => break Ok(status),
                                    },
                                    Err(err) => break Err(err),
                                }
                            };

                            *ask_to_exit = true;
                            result
                        }
                    }
                    #[cfg(unix)]
                    CommunicationChannel::Pipe => {
                        return Err(
                            "Pipe channel is not supported for this version of rtal".to_string()
                        );
                    }
                };
                // END: Handle channels
                let output_files = match output_files {
                    Ok(x) => x,
                    Err(x) => return Err(x),
                };
                let mut to_write = Vec::new();
                for _ in 0..output_files.len() {
                    let (name, data) = recv_binary_data(wsin).await?;
                    to_write.push((name, data));
                }
                if to_write.len() > 0 {
                    tokio::fs::create_dir_all(&output)
                        .await
                        .map_err(|x| format!("Cannot create {:?}: {}", &output, x))?;
                }
                for (name, data) in to_write {
                    let filename = output.join(name);
                    tokio::fs::write(&filename, data)
                        .await
                        .map_err(|x| format!("Cannot write {:?}: {}", filename, x))?;
                    println!("Received {:?}", &filename);
                }
                Ok(())
            }
            Command::Login { cred_file } => {
                let login_file = auth::resolve_login_file(cred_file)?;
                if get_valid_credentials(wsout, wsin, ask_to_exit, &login_file)
                    .await
                    .is_ok()
                {
                    return Err(format!(
                        "Already authenticated, run `rtal logout` to remove the authentication data and retry",
                    ));
                }

                auth::do_client_authentication(wsout, wsin, ask_to_exit, &login_file, uri).await
            }
            Command::Logout { cred_file } => {
                let login_file = auth::resolve_login_file(cred_file)?;
                auth::do_logout(&login_file)
            }
        }
    }
}

pub enum RunResult {
    Restart,
    Terminate { status: Vec<String> },
}

async fn handle_connection<
    T: Sink<Message> + Unpin,
    U: Stream<Item = Result<Message, TsError>> + Unpin,
    X: AsyncRead + Unpin,
    Y: AsyncWrite + Unpin,
>(
    wsout: &mut T,
    wsin: &mut U,
    mut pipein: X,
    mut pipeout: Y,
    echo: bool,
) -> Result<RunResult, String>
where
    <T as Sink<Message>>::Error: Display,
{
    let mut closing = false;
    let mut buffer = [0; BUFFER_SIZE];
    let mut last_print_client = None;
    let client_ended = Request::ConnectStop {};
    let client_ended = match client_ended.forge() {
        Ok(x) => x,
        Err(x) => return Err(format!("Cannot forge request: {}", x)),
    };
    loop {
        select! {
            msg = wsin.next() => {
                match msg {
                    Some(Ok(Message::Binary(x))) if !closing => {
                        if echo {
                            match last_print_client {
                                None | Some(true) => {
                                    println!("[SERVER]");
                                    last_print_client = Some(false);
                                }
                                _ => {}
                            }
                            print!("{}", String::from_utf8_lossy(&x));
                        }
                        let mut close = false;
                        if let Err(x) = pipeout.write_all(&x).await {
                            warn!("Cannot write to user: {}", x);
                            close = true;
                        }
                        if let Err(x) = pipeout.flush().await {
                            warn!("Cannot flush stream: {}", x);
                            close = true;
                        }
                        if close {
                            if let Err(x) = wsout.send(Message::Text(client_ended.clone())).await {
                                break Err(format!("Cannot send data to server: {}", x));
                            }
                            closing = true;
                        }
                    }
                    Some(Ok(Message::Text(x))) => match Reply::parse(&x) {
                        Ok(Reply::ConnectStop { status }) => {
                            if !closing {
                                if let Err(x) = wsout.send(Message::Text(client_ended.clone())).await {
                                    break Err(format!("Cannot send data to server: {}", x));
                                }
                            }
                            break status.map(|status| RunResult::Terminate { status });
                        }
                        Ok(Reply::ConnectNewSubtask { status: _ }) => {
                            break Ok(RunResult::Restart);
                        }
                        Ok(_) => break Err(format!("Received wrong message from server")),
                        Err(x) => break Err(format!("Cannot parse server reply: {}", x)),
                    }
                    Some(Ok(_)) => continue,
                    Some(Err(x)) => break Err(format!("Connection lost: {}", x)),
                    None => break Err(format!("Connection lost")),
                };
            }
            size = pipein.read(&mut buffer), if !closing => {
                let size = match size {
                    Ok(0) => {
                        if let Err(x) = wsout.send(Message::Text(client_ended.clone())).await {
                            break Err(format!("Cannot send data to server: {}", x));
                        }
                        closing = true;
                        continue;
                    }
                    Ok(x) => x,
                    Err(x) => {
                        warn!("Cannot read from user: {}", x);
                        if let Err(x) = wsout.send(Message::Text(client_ended.clone())).await {
                            break Err(format!("Cannot send data to server: {}", x));
                        }
                        closing = true;
                        continue;
                    }
                };
                if echo {
                    match last_print_client {
                        None | Some(false) => {
                            println!("[CLIENT]");
                            last_print_client = Some(true);
                        }
                        _ => {}
                    }
                    print!("{}", String::from_utf8_lossy(&buffer[..size]));
                }
                if let Err(x) = wsout.send(Message::Binary(buffer[..size].into())).await {
                    break Err(format!("Cannot send data to server: {}", x));
                }
            }
        }
    }
}

async fn start(args: CliArgs, ask_to_exit: &mut bool) -> Result<(), String> {
    let mut ws = match connect_async(&args.server_url).await {
        Ok(x) => x.0,
        Err(x) => return Err(format!("Cannot connect to \"{}\": {}", args.server_url, x)),
    };
    let result = match ws.get_mut() {
        &mut MaybeTlsStream::Plain(ref mut x) => x.set_nodelay(true),
        &mut MaybeTlsStream::Rustls(ref mut x) => x.get_mut().0.set_nodelay(true),
        &mut _ => unreachable!("Using stream other than Plain or Rustls"),
    };
    if let Err(x) = result {
        warn!("Cannot set TCP_NODELAY: {}", x);
    }
    let (mut wsout, mut wsin) = ws.split();
    let handshake_request = match Request::forge(&Request::Handshake {
        magic: proto::MAGIC.to_string(),
        version: proto::VERSION,
    }) {
        Ok(x) => Message::Text(x),
        Err(x) => return Err(format!("Cannot forge handshake request: {}", x)),
    };
    if let Err(x) = wsout.send(handshake_request).await {
        return Err(format!("Cannot send handshake request: {}", x));
    };
    let handshake_reply = loop {
        if let Some(msg) = wsin.next().await {
            match msg {
                Ok(Message::Text(x)) => match Reply::parse(&x) {
                    Ok(Reply::Handshake { magic, version }) => break (magic, version),
                    Ok(_) => return Err(format!("Server performed a wrong handshake")),
                    Err(x) => return Err(format!("Could not parse server handshake: {}", x)),
                },
                Err(x) => return Err(format!("Connection lost while performing handshake: {}", x)),
                Ok(_) => {}
            }
        } else {
            return Err(format!("Connection lost while performing handshake"));
        }
    };
    if !(handshake_reply.0 == proto::MAGIC && handshake_reply.1 == proto::VERSION) {
        return if handshake_reply.0 == proto::MAGIC {
            Err(format!(
                "Protocol version mismatch: local={}, server={}",
                proto::VERSION,
                handshake_reply.1
            ))
        } else {
            Err(format!(
                "\"{}\" is not a Turing Arena Light server",
                args.server_url
            ))
        };
    }
    args.command
        .run(&args.server_url, &mut wsout, &mut wsin, ask_to_exit)
        .await?;
    ws = match wsin.reunite(wsout) {
        Ok(x) => x,
        Err(x) => return Err(format!("Cannot reunite streams {}", x)),
    };
    match ws.close(None).await {
        Ok(()) | Err(TsError::ConnectionClosed) => {}
        Err(x) => warn!("Could not close connection to server gracefully: {}", x),
    }
    Ok(())
}

fn init_logging() {
    if let Err(x) = tracing_subscriber::fmt()
        .event_format(
            tracing_subscriber::fmt::format()
                .without_time()
                .with_target(false),
        )
        //.with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()
    {
        println!("Cannot enable logging service: {}", x);
    }
}

fn main() {
    init_logging();
    let args = CliArgs::parse();
    match Runtime::new() {
        Ok(rt) => rt.block_on(async move {
            let mut ask_to_exit = false;
            match start(args, &mut ask_to_exit).await {
                Ok(()) => {}
                Err(x) => error!("{}", x),
            }
            if ask_to_exit {
                println!("[Press ENTER to exit]");
            }
        }),
        Err(x) => error!("Cannot create tokio runtime: {}", x),
    };
}
