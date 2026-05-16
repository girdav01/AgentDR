//! Telemetry ingest paths.
//!
//! `otlp` exposes an OpenTelemetry Protocol (OTLP/HTTP) endpoint on the
//! loopback interface and maps OTel `gen_ai.*` semantic-convention attributes
//! into the CoSAI AITF / OCSF Category 7 event model.

pub mod otlp;
