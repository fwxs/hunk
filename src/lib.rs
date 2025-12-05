pub mod commands;
pub mod encoder;

pub trait CommandHandler {
    fn handle(self);
}
