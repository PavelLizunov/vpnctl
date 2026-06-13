//! Subcommand handlers. One module per resource group; thin glue between
//! `clap`-parsed args and crate functions.

pub(crate) mod admin;
pub(crate) mod backup;
pub(crate) mod bootstrap;
pub(crate) mod deploy;
pub(crate) mod geoip;
pub(crate) mod grant;
pub(crate) mod migrate;
pub(crate) mod registry_cmd;
pub(crate) mod render;
pub(crate) mod server;
pub(crate) mod status;
pub(crate) mod sub;
pub(crate) mod update_kernels;
pub(crate) mod user;
