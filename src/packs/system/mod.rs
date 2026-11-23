//! System pack - protections for system administration commands.
//!
//! This pack provides protection against destructive system operations:
//! - Disk operations (dd, fdisk, mkfs)
//! - Permission changes (chmod, chown with dangerous patterns)
//! - Service management (systemctl, service)
//! - Process signals by pattern, tree walk or broadcast (pkill, killall, kill -1; opt-in)

pub mod disk;
pub mod permissions;
pub mod processes;
pub mod services;
