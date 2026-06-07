namespace CmProjectX.Store;

// The DURABLE system-of-record for the audit/drift time-machine.
// IMPORTANT: this is NOT the IC LiteDB cache (that 24h-TTL cache is a Graph
// accelerator). This store is APPEND-ONLY and never expires — that permanence
// is the whole value prop (outliving Microsoft's audit retention).
//
// MVP target: SQLite for snapshots/audit + Lucene.NET for full-text search.

public interface ISnapshotStore
{
    // Append-only writes (never mutate/delete history).
    Task AppendAuditEventAsync(AuditEventRecord evt, CancellationToken ct = default);
    Task AppendSnapshotAsync(ConfigSnapshotRecord snapshot, CancellationToken ct = default);

    // Reads for the timeline / drift / search surfaces.
    Task<IReadOnlyList<AuditEventRecord>> QueryAuditAsync(
        DateTime? from, DateTime? to, string? q, CancellationToken ct = default);

    Task<ConfigSnapshotRecord?> GetSnapshotAsync(string snapshotId, CancellationToken ct = default);
}

// Placeholder records — replace with types generated from contract/openapi.yaml.
public sealed record AuditEventRecord(
    string Id, DateTime Timestamp, string? Actor, string Action,
    string ObjectType, string ObjectId, string? ObjectName);

public sealed record ConfigSnapshotRecord(
    string SnapshotId, string ObjectId, string ObjectType,
    DateTime CapturedUtc, string BodyJson);

// TODO: SQLite + Lucene.NET implementation.
public sealed class SnapshotStore : ISnapshotStore
{
    public Task AppendAuditEventAsync(AuditEventRecord evt, CancellationToken ct = default)
        => throw new NotImplementedException();

    public Task AppendSnapshotAsync(ConfigSnapshotRecord snapshot, CancellationToken ct = default)
        => throw new NotImplementedException();

    public Task<IReadOnlyList<AuditEventRecord>> QueryAuditAsync(
        DateTime? from, DateTime? to, string? q, CancellationToken ct = default)
        => throw new NotImplementedException();

    public Task<ConfigSnapshotRecord?> GetSnapshotAsync(string snapshotId, CancellationToken ct = default)
        => throw new NotImplementedException();
}
