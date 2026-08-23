//! Server action admin handlers: the write side of the servers surface —
//! traffic limits, protocol/kernel enable-disable, grants (single + bulk),
//! deploy, quick-add, delete, deploy-key push, the per-server config
//! setters and protocol hide/unhide. The read-only server list lives in
//! `servers.rs`. Extracted from `legacy.rs` as part of the admin
//! submodules refactor.

mod config;
mod deploy;
mod grants;
mod kernels;
mod lifecycle;
mod protocols;

pub(crate) use self::config::*;
pub(crate) use self::deploy::*;
pub(crate) use self::grants::*;
pub(crate) use self::kernels::*;
pub(crate) use self::lifecycle::*;
pub(crate) use self::protocols::*;
