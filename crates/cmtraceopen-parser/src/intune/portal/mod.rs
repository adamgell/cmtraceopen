// Company Portal parsing surfaces, grouped by the platform the artifact came from.
//
// Company Portal is a first-class `intune::portal` surface: it spans sign-in, enrollment,
// app catalog, compliance, sync, device actions, and support. Company Portal artifacts are
// deliberately NOT routed through the IME or ESP pipelines even where the workflows overlap.

pub mod ios_ipados;
