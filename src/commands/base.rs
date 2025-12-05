// TODO: Add Compression options
// TODO: Add Encryption options
// TODO: Add different Exfiltration methods
// TODO: Add scheduling support
// TODO: Add logging options
// TODO: Add retry mechanisms
// TODO: Add progress indicators

use crate::CommandHandler;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub operation_type: Operations,
}

impl Cli {
    pub fn handle(self) {
        self.operation_type.handle();
    }
}

#[derive(Debug, Subcommand)]
pub enum Operations {
    #[command(name = "exfil")]
    Exfiltration(super::exfiltrate::ExfiltrationSubCommandArgs),
}

impl CommandHandler for Operations {
    fn handle(self) {
        match self {
            Operations::Exfiltration(exfil_sub_cmd_args) => exfil_sub_cmd_args.handle(),
        }
    }
}
