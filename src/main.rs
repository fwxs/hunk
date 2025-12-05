use clap::Parser;

fn main() {
    hunk::commands::base::Cli::parse().handle();
}
