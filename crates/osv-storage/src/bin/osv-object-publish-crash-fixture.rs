//! Test-only subprocess for killing object publication at durable boundaries.

use std::{
    env,
    io::{self, Read, Write},
    path::Path,
    process::ExitCode,
};

use osv_crypto::{KdfParams, Password, SystemRandom};
use osv_storage::{
    MIN_CHUNK_SIZE, ObjectRole, PUBLISH_POINTS, PublishFaultInjector, PublishPoint, UnlockedVault,
};

const PLAINTEXT: &[u8] = b"phase four crash publication plaintext canary";

struct StopAt(PublishPoint);

impl PublishFaultInjector for StopAt {
    fn should_fail(&mut self, point: PublishPoint) -> bool {
        if point != self.0 {
            return false;
        }
        println!("{}", point.name());
        io::stdout().flush().expect("flush crash boundary");
        let _ = io::stdin().read(&mut [0_u8; 1]);
        false
    }
}

fn main() -> ExitCode {
    run().map_or_else(
        |message| {
            eprintln!("{message}");
            ExitCode::FAILURE
        },
        |()| ExitCode::SUCCESS,
    )
}

fn run() -> Result<(), &'static str> {
    let mut arguments = env::args_os().skip(1);
    let path = arguments.next().ok_or("missing fixture path")?;
    let selected = arguments.next().ok_or("missing boundary")?;
    if arguments.next().is_some() {
        return Err("unexpected fixture argument");
    }
    let selected = selected
        .to_str()
        .and_then(|name| {
            PUBLISH_POINTS
                .into_iter()
                .find(|point| point.name() == name)
        })
        .ok_or("invalid boundary")?;
    let password =
        Password::new(b"object fixture password").map_err(|_| "password allocation failed")?;
    let params = KdfParams::new(8, 1, 1).map_err(|_| "invalid fixture KDF")?;
    let vault = UnlockedVault::create(Path::new(&path), &password, None, params)
        .map_err(|_| "fixture create failed")?;
    let mut source = PLAINTEXT;
    vault
        .publish_object_with(
            &mut source,
            PLAINTEXT.len() as u64,
            ObjectRole::Original,
            MIN_CHUNK_SIZE,
            &mut SystemRandom,
            &mut StopAt(selected),
        )
        .map_err(|_| "fixture publication failed")?;
    Ok(())
}
