//! Subcommand handlers. One module per resource group; thin glue between
//! `clap`-parsed args and crate functions.

pub(crate) mod grant;
pub(crate) mod registry_cmd;
pub(crate) mod server;
pub(crate) mod user;
