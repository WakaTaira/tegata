use serde_json::{Value, json};
use std::io::{self, IsTerminal, Read};
use zeroize::Zeroize;

use super::JSON_RPC_VERSION;
use super::transport::pipe_path;

#[derive(clap::Subcommand)]
pub(crate) enum WindowsCommand {
    Status {
        #[arg(long, default_value = "tegatad")]
        pipe: String,
    },
    Token {
        #[command(subcommand)]
        command: TokenCommand,
    },
    Seal {
        #[arg(long, default_value = "tegatad")]
        pipe: String,
    },
    Service {
        #[command(subcommand)]
        command: super::windows_service::ServiceCommand,
    },
}

#[derive(clap::Subcommand)]
pub(crate) enum TokenCommand {
    Issue {
        #[arg(long, default_value = "tegatad")]
        pipe: String,
    },
}

pub(crate) fn run_windows_cli(
    pipe_name: &str,
    method: &str,
    params: Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(call_pipe_rpc(pipe_name, method, params))?;
    if let Some(message) = response
        .get("error")
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
    {
        return Err(io::Error::other(message.to_owned()).into());
    }
    match method {
        "status" => println!("{}", serde_json::to_string(&response)?),
        "admin_token_issue" => {
            let token = response
                .get("result")
                .and_then(|result| result.get("token"))
                .and_then(Value::as_str)
                .ok_or("admin_token_issue returned no token")?;
            println!("{token}");
        }
        "admin_seal" => {}
        _ => {}
    }
    Ok(())
}

async fn call_pipe_rpc(pipe_name: &str, method: &str, params: Value) -> io::Result<Value> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::ClientOptions;

    let mut client = ClientOptions::new().open(pipe_path(pipe_name)?)?;
    let request = json!({
        "jsonrpc": JSON_RPC_VERSION,
        "id": 1,
        "method": method,
        "params": params,
    });
    client
        .write_all(
            format!(
                "{}\n",
                serde_json::to_string(&request)
                    .map_err(|error| { io::Error::new(io::ErrorKind::InvalidData, error) })?
            )
            .as_bytes(),
        )
        .await?;
    client.flush().await?;
    let mut line = String::new();
    let read = BufReader::new(client).read_line(&mut line).await?;
    if read == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "pipe RPC connection closed",
        ));
    }
    serde_json::from_str(&line).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

pub(crate) fn read_master_password() -> io::Result<String> {
    if !io::stdin().is_terminal() {
        let mut password = String::new();
        if let Err(error) = io::stdin().read_to_string(&mut password) {
            password.zeroize();
            return Err(error);
        }
        let result = password.trim_end_matches(['\r', '\n']).to_owned();
        password.zeroize();
        return Ok(result);
    }
    read_console_password()
}

fn read_console_password() -> io::Result<String> {
    use windows_sys::Win32::System::Console::{
        ENABLE_ECHO_INPUT, GetConsoleMode, GetStdHandle, ReadConsoleW, STD_INPUT_HANDLE,
        SetConsoleMode,
    };

    // SAFETY: The standard input handle is obtained from the current console process.
    let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let mut mode = 0;
    // SAFETY: `mode` is a valid output pointer for the standard input handle.
    if unsafe { GetConsoleMode(handle, &mut mode) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: The handle is valid, and the mode was returned by GetConsoleMode.
    if unsafe { SetConsoleMode(handle, mode & !ENABLE_ECHO_INPUT) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buffer = [0_u16; 1024];
    let mut read = 0_u32;
    // SAFETY: `buffer` and `read` are valid write destinations with their lengths specified.
    let result = unsafe {
        ReadConsoleW(
            handle,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
            &mut read,
            std::ptr::null(),
        )
    };
    // SAFETY: The handle is valid, and `mode` is the mode saved before echo was disabled.
    let restored = unsafe { SetConsoleMode(handle, mode) };
    let value = if result == 0 || restored == 0 {
        Err(io::Error::last_os_error())
    } else {
        let _ = std::io::Write::write_all(&mut io::stdout(), b"\n");
        Ok(String::from_utf16_lossy(&buffer[..read as usize])
            .trim_end_matches(['\r', '\n'])
            .to_owned())
    };
    buffer.zeroize();
    value
}
