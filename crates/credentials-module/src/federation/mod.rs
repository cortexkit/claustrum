//! Federation: the vault as a member of a set of machines, each with its own vault.
//!
//! The federation work is split by surface: the outbound client calls a peer vault,
//! the ingress side answers a peer's call, the remote read serves this vault's
//! consumers from a home vault, and transfers move static keys. Only the outbound
//! client exists so far; the rest are added here as they are built, so every entry
//! point is reached as `federation::*`.

pub mod outbound;

pub use outbound::{
    bind_identity, management_surface, OutboundClient, OutboundError, RouteCall, ADMIN_OP_BUDGET,
    CONSUMER_FACING_DEADLINE, HOME_OP_DEADLINE,
};
