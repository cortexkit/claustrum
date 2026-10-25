//! Federation: the vault as a member of a set of machines, each with its own vault.
//!
//! The campaign's other files land in their own slices; this module holds what the
//! outbound client needs and re-exports them from here, so every entry point names
//! `federation::*` and the module keeps one layout whatever order the slices merge in.

pub mod outbound;

pub use outbound::{
    bind_identity, management_surface, OutboundClient, OutboundError, RouteCall, ADMIN_OP_BUDGET,
    CONSUMER_FACING_DEADLINE, HOME_OP_DEADLINE,
};
