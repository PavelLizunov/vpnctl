mod executor;
mod parsers;
mod planner;
mod types;

#[cfg(test)]
mod tests;

pub use executor::apply_migration_plan;
pub use parsers::{parse_bash_inventory_env, parse_bash_singbox};
pub use planner::{build_migration_plan, derive_server_id_from_ip};
pub use types::{
    BashInventoryEnv, BashSingboxData, BashTuicUser, BashVlessUser, MigrationOutcome,
    MigrationPlan, SkippedUser,
};
