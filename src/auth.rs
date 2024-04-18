use base64::Engine;
use futures_util::{Sink, Stream};
use std::{
    fmt::Display,
    fs::create_dir_all,
    path::{Path, PathBuf},
};
use tokio_tungstenite::tungstenite::Error as TsError;
use tungstenite::{http::Uri, Message};

use crate::{
    proto::{Reply, Request},
    util::oneshot_request,
};

pub fn resolve_login_file(cred_file: Option<PathBuf>, server_url: &str) -> Result<PathBuf, String> {
    Ok(match cred_file {
        Some(x) => x,
        None => {
            let mut path = dirs::config_dir()
                .ok_or("Cannot find config directory, manually specify the cred_file")?;
            path.push("rtal-");
            path.push(base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(server_url));
            path.push("-login.token");
            path
        }
    })
}

pub fn load_credentials(path: &Path) -> Result<(String, String), String> {
    let creds = std::fs::read_to_string(path);

    let (matricola, token) = match &creds {
        Ok(x) => {
            let mut parts = x.split(',');
            let matricola = parts.next().unwrap_or("");
            let token = parts.next().unwrap_or("");
            (matricola, token)
        }
        Err(e) => {
            return Err(format!("Cannot read login file: {}", e));
        }
    };

    Ok((matricola.to_string(), token.to_string()))
}

pub async fn get_valid_credentials<
    T: Sink<Message> + Unpin,
    U: Stream<Item = Result<Message, TsError>> + Unpin,
>(
    wsout: &mut T,
    wsin: &mut U,
    _ask_to_exit: &mut bool,
    path: &Path,
) -> Result<(String, String), String>
where
    <T as Sink<Message>>::Error: Display,
{
    let (matricola, token) = load_credentials(path)?;

    let request = Request::CheckTokenValidity {
        token: token.to_string(),
    };
    match oneshot_request(request, wsout, wsin).await? {
        Reply::IsTokenValid { valid } => {
            if valid {
                Ok((matricola.to_string(), token.to_string()))
            } else {
                Err("Credentials are not valid".to_string())
            }
        }
        reply => Err(format!("Server sent an invalid response {:?}", reply)),
    }
}

pub async fn do_client_authentication<
    T: Sink<Message> + Unpin,
    U: Stream<Item = Result<Message, TsError>> + Unpin,
>(
    wsout: &mut T,
    wsin: &mut U,
    _ask_to_exit: &mut bool,
    login_path: &Path,
    websocket_url: &str,
) -> Result<(), String>
where
    <T as Sink<Message>>::Error: Display,
{
    if let Some(parent) = login_path.parent() {
        let _ = create_dir_all(&parent);
    }

    let request = Request::GenerateToken {};
    let token = match oneshot_request(request, wsout, wsin).await? {
        Reply::CreatedToken { token } => token,
        reply => return Err(format!("Server sent an invalid response {:?}", reply)),
    };
    let matricola = rprompt::prompt_reply("Matricola: ").map_err(|err| err.to_string())?;
    let matricola = matricola.trim();

    if !matricola.starts_with("VR")
        || matricola.chars().any(|a| !a.is_ascii_alphanumeric())
        || matricola.len() < 4
        || matricola.len() > 10
    {
        return Err("Invalid matricola".to_string());
    }

    let matricola = urlencoding::encode(matricola);
    let url_token = urlencoding::encode(&token);
    let websocket_url = urlencoding::encode(&websocket_url);
    let uri = Uri::builder()
        .scheme("https")
        .authority("ta.di.univr.it")
        .path_and_query(format!(
            "/?matricola={}&authKey={}&rtalWebSocket={}",
            matricola, url_token, websocket_url
        ))
        .build()
        .expect("Cannot build URI");

    std::fs::write(login_path, format!("{},{}", matricola, token))
        .map_err(|e| format!("Cannot write login file: {}", e))?;

    println!("Complete the authentication at the following URL: {}", uri);
    Ok(())
}

pub fn do_logout(login_path: &Path) -> Result<(), String> {
    if login_path.exists() {
        std::fs::remove_file(login_path).map_err(|e| format!("Cannot remove login file: {}", e))?;
        println!("Logged out");
    }
    Ok(())
}
