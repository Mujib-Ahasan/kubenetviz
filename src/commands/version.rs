use anyhow::Result;

pub fn run() -> Result<()> {
    println!("kubenetviz {}", env!("CARGO_PKG_VERSION"));
    Ok(())
}