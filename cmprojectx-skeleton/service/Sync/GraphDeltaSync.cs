using CmProjectX.Store;

namespace CmProjectX.Sync;

// Incremental sync engine. Pulls Intune audit events + config object snapshots
// via Microsoft Graph and appends them to the durable store.
//
// MUST use Graph DELTA queries (track deltaLink per object type) + throttling/
// backoff — never naive full pulls. Reuse the hard-forked IC Graph services.
public sealed class GraphDeltaSync
{
    private readonly ISnapshotStore _store;

    public GraphDeltaSync(ISnapshotStore store) => _store = store;

    public Task RunAsync(CancellationToken ct = default)
    {
        // TODO:
        //  1. For each tracked object type, call IC Graph service with its delta token.
        //  2. Append new ConfigSnapshotRecord per changed object (append-only).
        //  3. Pull deviceManagement audit events; append AuditEventRecord.
        //  4. Persist updated delta tokens; honor Retry-After throttling.
        _ = _store;
        throw new NotImplementedException();
    }
}
