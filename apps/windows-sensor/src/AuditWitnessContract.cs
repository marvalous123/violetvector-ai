using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WARRoom.WindowsSensor;

public sealed record AuditWitnessRecord(
    int SchemaVersion,
    string Purpose,
    string Phase,
    string ChainId,
    long Sequence,
    string PreviousRecordHash,
    string PreviousEventHash,
    string EventHash,
    string OccurredAtUtc,
    string PrepareRecordHash,
    string RecordHash);

public sealed record AuditWitnessPendingPrepare(
    long Sequence,
    string PreviousEventHash,
    string EventHash,
    string OccurredAtUtc,
    string RecordHash);

public sealed record AuditWitnessState(
    string ChainId,
    long CommittedSequence,
    string CommittedEventHash,
    long RecordCount,
    string LastRecordHash,
    AuditWitnessPendingPrepare? PendingPrepare);

public sealed record AuditWitnessDatabaseObservation(
    long DatabaseHeadSequence,
    string DatabaseHeadEventHash);

public sealed record AuditWitnessReconciliation(
    string Status,
    bool AppendCommitAllowed,
    bool OperatorReviewRequired,
    string? PrepareRecordHash);

public static class AuditWitnessContract
{
    public const int SchemaVersion = 1;
    public const string Purpose = "project15.audit-witness-record.v1";
    public const string Claim = "historical-rewrite-detection-only";
    public const string PreparePhase = "PREPARE";
    public const string CommitPhase = "COMMIT";
    public const string AbortPhase = "ABORT";
    public const long MaximumSequence = 9_007_199_254_740_991;
    public static string GenesisHash { get; } = new('0', 64);

    public static AuditWitnessState CreateGenesisState(string chainId)
    {
        if (!IsNonGenesisHash(chainId))
        {
            throw Invalid("SENSOR_AUDIT_WITNESS_CHAIN_INVALID");
        }
        return new(chainId, 0, GenesisHash, 0, GenesisHash, null);
    }

    public static AuditWitnessRecord CreatePrepare(
        AuditWitnessState currentState,
        string eventHash,
        string occurredAtUtc)
    {
        var state = ValidateState(currentState);
        if (state.PendingPrepare is not null)
        {
            throw Invalid("SENSOR_AUDIT_WITNESS_PREPARE_ALREADY_PENDING");
        }
        if (!IsNonGenesisHash(eventHash) || !IsCanonicalUtc(occurredAtUtc))
        {
            throw Invalid("SENSOR_AUDIT_WITNESS_EVENT_INVALID");
        }

        var record = new AuditWitnessRecord(
            SchemaVersion,
            Purpose,
            PreparePhase,
            state.ChainId,
            checked(state.CommittedSequence + 1),
            state.LastRecordHash,
            state.CommittedEventHash,
            eventHash,
            occurredAtUtc,
            GenesisHash,
            string.Empty);
        return record with { RecordHash = RecordHash(record) };
    }

    public static AuditWitnessRecord CreateCommit(
        AuditWitnessState currentState,
        AuditWitnessDatabaseObservation observation)
    {
        var state = ValidateState(currentState);
        var reconciliation = Reconcile(state, observation);
        var pending = state.PendingPrepare;
        if (
            reconciliation.Status !=
                "database-committed-awaiting-commit" ||
            pending is null)
        {
            throw Invalid("SENSOR_AUDIT_WITNESS_COMMIT_NOT_ALLOWED");
        }

        var record = new AuditWitnessRecord(
            SchemaVersion,
            Purpose,
            CommitPhase,
            state.ChainId,
            pending.Sequence,
            pending.RecordHash,
            pending.PreviousEventHash,
            pending.EventHash,
            pending.OccurredAtUtc,
            pending.RecordHash,
            string.Empty);
        return record with { RecordHash = RecordHash(record) };
    }

    public static AuditWitnessRecord CreateAbort(
        AuditWitnessState currentState,
        AuditWitnessDatabaseObservation observation,
        bool operatorReviewConfirmed)
    {
        if (!operatorReviewConfirmed)
        {
            throw Invalid(
                "SENSOR_AUDIT_WITNESS_ABORT_OPERATOR_REVIEW_REQUIRED");
        }
        var state = ValidateState(currentState);
        var reconciliation = Reconcile(state, observation);
        var pending = state.PendingPrepare;
        if (
            reconciliation.Status != "prepare-not-database-committed" ||
            pending is null)
        {
            throw Invalid("SENSOR_AUDIT_WITNESS_ABORT_NOT_ALLOWED");
        }

        var record = new AuditWitnessRecord(
            SchemaVersion,
            Purpose,
            AbortPhase,
            state.ChainId,
            pending.Sequence,
            pending.RecordHash,
            pending.PreviousEventHash,
            pending.EventHash,
            pending.OccurredAtUtc,
            pending.RecordHash,
            string.Empty);
        return record with { RecordHash = RecordHash(record) };
    }

    public static AuditWitnessState Advance(
        AuditWitnessState currentState,
        AuditWitnessRecord record)
    {
        var state = ValidateState(currentState);
        ValidateRecord(record);
        if (record.ChainId != state.ChainId)
        {
            throw Invalid("SENSOR_AUDIT_WITNESS_CHAIN_MISMATCH");
        }
        if (record.PreviousRecordHash != state.LastRecordHash)
        {
            throw Invalid("SENSOR_AUDIT_WITNESS_RECORD_FORK_DETECTED");
        }

        if (record.Phase == PreparePhase)
        {
            if (state.PendingPrepare is not null)
            {
                throw Invalid(
                    "SENSOR_AUDIT_WITNESS_PREPARE_ALREADY_PENDING");
            }
            if (
                record.Sequence != state.CommittedSequence + 1 ||
                record.PreviousEventHash != state.CommittedEventHash)
            {
                throw Invalid("SENSOR_AUDIT_WITNESS_SEQUENCE_INVALID");
            }
            return ValidateState(state with
            {
                RecordCount = checked(state.RecordCount + 1),
                LastRecordHash = record.RecordHash,
                PendingPrepare = new(
                    record.Sequence,
                    record.PreviousEventHash,
                    record.EventHash,
                    record.OccurredAtUtc,
                    record.RecordHash)
            });
        }

        var pending = state.PendingPrepare;
        if (pending is null)
        {
            throw Invalid("SENSOR_AUDIT_WITNESS_COMMIT_WITHOUT_PREPARE");
        }
        if (
            record.Sequence != pending.Sequence ||
            record.PreviousEventHash != pending.PreviousEventHash ||
            record.EventHash != pending.EventHash ||
            record.OccurredAtUtc != pending.OccurredAtUtc ||
            record.PrepareRecordHash != pending.RecordHash ||
            record.PreviousRecordHash != pending.RecordHash)
        {
            throw Invalid(
                record.Phase == AbortPhase
                    ? "SENSOR_AUDIT_WITNESS_ABORT_BINDING_INVALID"
                    : "SENSOR_AUDIT_WITNESS_COMMIT_BINDING_INVALID");
        }
        if (record.Phase == AbortPhase)
        {
            return ValidateState(state with
            {
                RecordCount = checked(state.RecordCount + 1),
                LastRecordHash = record.RecordHash,
                PendingPrepare = null
            });
        }
        return ValidateState(new(
            state.ChainId,
            record.Sequence,
            record.EventHash,
            checked(state.RecordCount + 1),
            record.RecordHash,
            null));
    }

    public static AuditWitnessReconciliation Reconcile(
        AuditWitnessState currentState,
        AuditWitnessDatabaseObservation observation)
    {
        var state = ValidateState(currentState);
        ArgumentNullException.ThrowIfNull(observation);
        if (
            observation.DatabaseHeadSequence < 0 ||
            observation.DatabaseHeadSequence > MaximumSequence ||
            !IsHash(observation.DatabaseHeadEventHash) ||
            (observation.DatabaseHeadSequence == 0) !=
                (observation.DatabaseHeadEventHash == GenesisHash))
        {
            throw Invalid(
                "SENSOR_AUDIT_WITNESS_DATABASE_OBSERVATION_INVALID");
        }
        if (observation.DatabaseHeadSequence < state.CommittedSequence)
        {
            throw Invalid(
                "SENSOR_AUDIT_WITNESS_DATABASE_TRUNCATION_DETECTED");
        }
        if (
            observation.DatabaseHeadSequence == state.CommittedSequence &&
            observation.DatabaseHeadEventHash != state.CommittedEventHash)
        {
            throw Invalid("SENSOR_AUDIT_WITNESS_DATABASE_FORK_DETECTED");
        }

        var pending = state.PendingPrepare;
        if (pending is null)
        {
            if (observation.DatabaseHeadSequence != state.CommittedSequence)
            {
                throw Invalid(
                    "SENSOR_AUDIT_WITNESS_DATABASE_AHEAD_WITHOUT_PREPARE");
            }
            return new("consistent", false, false, null);
        }
        if (observation.DatabaseHeadSequence == state.CommittedSequence)
        {
            return new(
                "prepare-not-database-committed",
                false,
                true,
                pending.RecordHash);
        }
        if (
            observation.DatabaseHeadSequence == pending.Sequence &&
            observation.DatabaseHeadEventHash == pending.EventHash)
        {
            return new(
                "database-committed-awaiting-commit",
                true,
                false,
                pending.RecordHash);
        }
        if (observation.DatabaseHeadSequence == pending.Sequence)
        {
            throw Invalid("SENSOR_AUDIT_WITNESS_DATABASE_FORK_DETECTED");
        }
        throw Invalid(
            "SENSOR_AUDIT_WITNESS_DATABASE_AHEAD_WITHOUT_PREPARE");
    }

    internal static string RecordHash(AuditWitnessRecord record)
    {
        byte[]? payload = null;
        try
        {
            payload = CanonicalPayload(record);
            return Convert.ToHexString(SHA256.HashData(payload))
                .ToLowerInvariant();
        }
        finally
        {
            if (payload is not null)
            {
                CryptographicOperations.ZeroMemory(payload);
            }
        }
    }

    internal static byte[] CanonicalPayload(AuditWitnessRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        using var buffer = new MemoryStream();
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions
        {
            Indented = false,
            SkipValidation = false
        }))
        {
            writer.WriteStartObject();
            writer.WriteString("chainId", record.ChainId);
            writer.WriteString("eventHash", record.EventHash);
            writer.WriteString("occurredAtUtc", record.OccurredAtUtc);
            writer.WriteString("phase", record.Phase);
            writer.WriteString(
                "prepareRecordHash",
                record.PrepareRecordHash);
            writer.WriteString("previousEventHash", record.PreviousEventHash);
            writer.WriteString(
                "previousRecordHash",
                record.PreviousRecordHash);
            writer.WriteString("purpose", record.Purpose);
            writer.WriteNumber("schemaVersion", record.SchemaVersion);
            writer.WriteNumber("sequence", record.Sequence);
            writer.WriteEndObject();
        }
        return buffer.ToArray();
    }

    private static void ValidateRecord(AuditWitnessRecord record)
    {
        ArgumentNullException.ThrowIfNull(record);
        if (
            record.SchemaVersion != SchemaVersion ||
            record.Purpose != Purpose ||
            record.Phase is not PreparePhase and not CommitPhase and
                not AbortPhase ||
            !IsNonGenesisHash(record.ChainId) ||
            record.Sequence is < 1 or > MaximumSequence ||
            !IsHash(record.PreviousRecordHash) ||
            !IsHash(record.PreviousEventHash) ||
            !IsNonGenesisHash(record.EventHash) ||
            !IsCanonicalUtc(record.OccurredAtUtc) ||
            !IsHash(record.PrepareRecordHash) ||
            (
                record.Phase == PreparePhase &&
                record.PrepareRecordHash != GenesisHash
            ) ||
            (
                record.Phase is CommitPhase or AbortPhase &&
                record.PrepareRecordHash == GenesisHash
            ) ||
            !IsNonGenesisHash(record.RecordHash))
        {
            throw Invalid("SENSOR_AUDIT_WITNESS_RECORD_SCHEMA_INVALID");
        }
        if (RecordHash(record) != record.RecordHash)
        {
            throw Invalid("SENSOR_AUDIT_WITNESS_RECORD_HASH_INVALID");
        }
    }

    private static AuditWitnessState ValidateState(AuditWitnessState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (
            !IsNonGenesisHash(state.ChainId) ||
            state.CommittedSequence is < 0 or > MaximumSequence ||
            state.RecordCount is < 0 or > MaximumSequence ||
            !IsHash(state.CommittedEventHash) ||
            !IsHash(state.LastRecordHash) ||
            (state.CommittedSequence == 0) !=
                (state.CommittedEventHash == GenesisHash) ||
            (
                (state.RecordCount == 0) !=
                    (state.LastRecordHash == GenesisHash)
            ) ||
            (
                state.RecordCount == 0 &&
                (state.CommittedSequence != 0 ||
                    state.PendingPrepare is not null)
            ))
        {
            throw Invalid("SENSOR_AUDIT_WITNESS_STATE_INVALID");
        }

        var pending = state.PendingPrepare;
        if (
            pending is not null &&
            (
                pending.Sequence != state.CommittedSequence + 1 ||
                pending.Sequence > MaximumSequence ||
                pending.PreviousEventHash != state.CommittedEventHash ||
                !IsNonGenesisHash(pending.EventHash) ||
                !IsCanonicalUtc(pending.OccurredAtUtc) ||
                !IsNonGenesisHash(pending.RecordHash) ||
                pending.RecordHash != state.LastRecordHash
            ))
        {
            throw Invalid("SENSOR_AUDIT_WITNESS_STATE_INVALID");
        }
        return state;
    }

    private static bool IsCanonicalUtc(string? value) =>
        value is not null &&
        DateTime.TryParseExact(
            value,
            "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out var parsed) &&
        parsed.ToString(
            "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
            CultureInfo.InvariantCulture) == value;

    private static bool IsNonGenesisHash(string? value) =>
        IsHash(value) && value != GenesisHash;

    private static bool IsHash(string? value) =>
        value is { Length: 64 } &&
        value.All(character =>
            character is >= '0' and <= '9' or >= 'a' and <= 'f');

    private static InvalidDataException Invalid(string code) => new(code);
}
