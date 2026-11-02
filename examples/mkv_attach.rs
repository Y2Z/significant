//! Exercises the Matroska layer alone: mkv_attach add|read|remove FILE
#[allow(dead_code)]
#[path = "../src/mkv.rs"]
mod mkv;

use std::fs::File;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let [_, action, path] = args.as_slice() else {
        return Err("usage: mkv_attach add|read|remove FILE".into());
    };
    let mut file = File::options().read(true).write(true).open(path)?;
    match action.as_str() {
        "add" => println!("{:?}", mkv::embed_placeholder(&mut file, &[0x5A; 4096])?),
        "read" => println!(
            "{:?}",
            mkv::read_payload(&mut file)?.map(|(p, at)| (p.len(), at))
        ),
        "remove" => println!("{}", mkv::remove(&mut file)?),
        _ => return Err("unknown action".into()),
    }
    Ok(())
}
