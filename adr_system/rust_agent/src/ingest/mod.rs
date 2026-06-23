//! Telemetry ingest paths.
//!
//! `otlp` exposes an OpenTelemetry Protocol (OTLP/HTTP) endpoint on the
//! loopback interface and maps OTel `gen_ai.*` semantic-convention attributes
//! into the CoSAI AITF OCSF Class-Reuse (ai_operation profile) event model.

pub mod otlp;
