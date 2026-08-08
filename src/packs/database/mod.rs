//! Database pack - protections for database management commands.
//!
//! This pack provides protection against destructive database operations:
//! - `PostgreSQL` (`psql`, `dropdb`, `pg_dump`)
//! - `MySQL`/`MariaDB` (`mysql`, `mysqldump`)
//! - `MongoDB` (`mongosh`, `mongodump`)
//! - `Redis` (`redis-cli`)
//! - `SQLite` (`sqlite3`)
//! - Snowflake (modern `snow sql` CLI)
//! - `BigQuery` (`bq` CLI and `GoogleSQL`)
//! - `Supabase` (`supabase db`, `supabase migration`, `supabase projects`)

pub mod bigquery;
pub mod mongodb;
pub mod mysql;
pub mod postgresql;
pub mod redis;
pub mod snowflake;
pub mod sqlite;
pub mod supabase;
