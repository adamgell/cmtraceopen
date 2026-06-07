// cmProjectX service — thin ASP.NET host in front of the hard-forked IC core.
// Endpoints mirror contract/openapi.yaml. All handlers are stubs (501) for now.
//
// Run as a LOCAL SIDECAR for the MVP (the Rust app launches it on 127.0.0.1).

using CmProjectX.Store;
using CmProjectX.Sync;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<ISnapshotStore, SnapshotStore>();
builder.Services.AddSingleton<GraphDeltaSync>();

var app = builder.Build();

// GET /health
app.MapGet("/health", () => Results.Ok(new
{
    healthy = true,
    tenantId = (string?)null,
    lastSyncUtc = (DateTime?)null,
    cloud = "Commercial",
}));

// POST /sync — trigger a Graph delta sync
app.MapPost("/sync", (GraphDeltaSync sync) =>
{
    // TODO: kick off background delta sync using the hard-forked IC Graph services.
    _ = sync;
    return Results.Accepted();
});

// GET /audit — the audit-event timeline (time-machine)
app.MapGet("/audit", (DateTime? from, DateTime? to, string? q, ISnapshotStore store) =>
{
    // TODO: query the append-only audit store.
    _ = (from, to, q, store);
    return Results.StatusCode(StatusCodes.Status501NotImplemented);
});

// GET /drift — drift between two config snapshots
app.MapGet("/drift", (string objectId, string? baseSnapshotId, string? headSnapshotId, ISnapshotStore store) =>
{
    // TODO: diff snapshots → DriftRecord.
    _ = (objectId, baseSnapshotId, headSnapshotId, store);
    return Results.StatusCode(StatusCodes.Status501NotImplemented);
});

// GET /search — full-text across audit + snapshots
app.MapGet("/search", (string q, ISnapshotStore store) =>
{
    // TODO: query the full-text index (Lucene.NET).
    _ = (q, store);
    return Results.StatusCode(StatusCodes.Status501NotImplemented);
});

app.Run("http://127.0.0.1:5099");
