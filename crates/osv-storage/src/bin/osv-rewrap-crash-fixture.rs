//! Test-only subprocess for killing credential rewrap at durable boundaries.

use std::{
    env,
    io::{self, Read, Write},
    path::Path,
    process::ExitCode,
};

use osv_crypto::{KdfParams, Password};
use osv_storage::{REWRAP_POINTS, RewrapFaultInjector, RewrapPoint, UnlockedVault};

struct StopAt(RewrapPoint);

impl RewrapFaultInjector for StopAt {
    fn should_fail(&mut self, point: RewrapPoint) -> bool {
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
        .and_then(|name| REWRAP_POINTS.into_iter().find(|point| point.name() == name))
        .ok_or("invalid boundary")?;
    let old = Password::new(b"old fixture password").map_err(|_| "password allocation failed")?;
    let new = Password::new(b"new fixture password").map_err(|_| "password allocation failed")?;
    let params = KdfParams::new(8, 1, 1).map_err(|_| "invalid fixture KDF")?;
    let mut vault = UnlockedVault::create(Path::new(&path), &old, None, params)
        .map_err(|_| "fixture create failed")?;
    vault
        .rewrap_with(
            &new,
            None,
            params,
            &mut osv_crypto::SystemRandom,
            &mut StopAt(selected),
        )
        .map_err(|_| "fixture rewrap failed")?;
    Ok(())
}
