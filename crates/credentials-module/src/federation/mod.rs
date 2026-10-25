//! Federation: the vault as a member of a set of machines, each with its own vault.
//!
//! The federation work is split by surface: the outbound client calls a peer vault,
//! the ingress side answers a peer's call, the remote read serves this vault's
//! consumers from a home vault, and transfers move static keys. The operator's admin
//! ops that need outbound calls (send, accept, remote add, member grant, the self id)
//! are dispatched by `AdminSurface` through the stage functions exported here. Every
//! entry point is reached as `federation::*`.

pub mod ingress;
pub mod outbound;
pub mod remote_read;
pub mod transfer;

pub use ingress::{
    callosum_lookup, carries_bearer, decode_paired_devices, decode_self_member, is_federation_op,
    map_route_caller, member_id_for_static_key, HomeAnswer, HomeVault, Lookup, MappingGate,
    RouteCaller,
};
pub use outbound::{
    bind_identity, management_surface, OutboundClient, OutboundError, RouteCall, ADMIN_OP_BUDGET,
    CONSUMER_FACING_DEADLINE, HOME_OP_DEADLINE,
};
pub use remote_read::{RemoteAnswer, RemoteGet, RemoteReader, RemoteRefusal};
pub use transfer::{
    transfer_eligibility, AcceptPlan, AcceptReport, AcceptStep, DeliveryReply, Ineligible,
    SendPlan, SendReport, TransferAad, TransferRefusal, Transfers, TRANSFER_INFO,
};
