use agent_core::{Client, Effort, Message, MessagesRequest, StopReason};
use anyhow::{Context, bail};

const MODEL: &str = "claude-opus-5-5";
/// Room for thinking plus the answer. Hitting it truncates the reply.
const MAX_TOKENS: u32 = 16_000;

// `#[tokio::main]` starts the async runtime and runs this async fn on it.
// Without a runtime, nothing would drive the `.await`s to completion.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load ANTHROPIC_API_KEY from .env if the file exists. A missing file is
    // fine (the key may already be in the environment); a broken one isn't.
    match dotenvy::dotenv() {
        Ok(_) => {}
        Err(error) if error.not_found() => {}
        Err(error) => return Err(error).context("couldn't read .env"),
    }

    let prompt = std::env::args().skip(1).collect::<Vec<_>>().join(" ");
    if prompt.trim().is_empty() {
        bail!("usage: rust-agent <prompt>   e.g. rust-agent \"Say hi in five words\"");
    }

    // Status goes to stderr and the answer to stdout, so
    // `rust-agent "..." > answer.txt` saves only Claude's reply.
    eprintln!("{} · {MODEL}", agent_core::banner());

    let client = Client::from_env()?;
    let request = MessagesRequest::new(MODEL, MAX_TOKENS, vec![Message::user(prompt)])
        .with_effort(Effort::Medium);

    let response = client
        .send(&request)
        .await
        .context("request to Claude failed")?;

    match response.stop_reason {
        Some(StopReason::Refusal) => bail!("Claude declined this request"),
        Some(StopReason::MaxTokens) => eprintln!("warning: reply hit max_tokens and is cut off"),
        _ => {}
    }

    println!("{}", response.text());
    eprintln!(
        "[{} · {} input + {} output tokens]",
        response.model, response.usage.input_tokens, response.usage.output_tokens
    );
    Ok(())
}
