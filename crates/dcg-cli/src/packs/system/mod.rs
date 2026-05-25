//! System pack - protections for system administration commands.
//!
//! This pack provides protection against destructive system operations:
//! - Disk operations (dd, fdisk, mkfs)
//! - Permission changes (chmod, chown with dangerous patterns)
//! - Service management (systemctl, service)

pub mod disk;
pub mod permissions;
pub mod services;
