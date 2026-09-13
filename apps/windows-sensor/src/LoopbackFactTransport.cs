using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace WARRoom.WindowsSensor;

public sealed record LoopbackFactReceipt(
    int SchemaVersion,
    string Status,
    string BatchHash,
    long BatchSequence,
    int FactCount);

public interface ILoopbackFactTransport
{
    Task<LoopbackFactReceipt> SendOnceAsync(
        LocalSyntheticSignedBatch batch,
        CancellationToken cancellationToken);
}

public sealed class LoopbackFactTransport : ILoopbackFactTransport, IDisposable
{
    public const string Destination =
        "http://127.0.0.1:4315/api/endpoints/facts";
    public const int MaximumRequestBytes = 32_768;
    public const int MaximumResponseBytes = 1_024;
    public const int TimeoutMilliseconds = 5_000;

    private static readonly Uri DestinationUri = new(Destination, UriKind.Absolute);
    private static readonly IReadOnlySet<string> OuterReceiptFields = ExactSet("receipt");
    private static readonly IReadOnlySet<string> ReceiptFields = ExactSet(
        "schemaVersion", "status", "batchHash", "batchSequence", "factCount");

    private readonly HttpMessageInvoker invoker;

    public LoopbackFactTransport() : this(CreateFixedHandler())
    {
    }

    internal LoopbackFactTransport(HttpMessageHandler handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        invoker = new HttpMessageInvoker(handler, disposeHandler: true);
    }

    internal static HttpClientHandler CreateFixedHandler() =>
        new()
        {
            AllowAutoRedirect = false,
            UseProxy = false,
            UseCookies = false,
            UseDefaultCredentials = false,
            AutomaticDecompression = DecompressionMethods.None,
            MaxConnectionsPerServer = 1
        };

    public async Task<LoopbackFactReceipt> SendOnceAsync(
        LocalSyntheticSignedBatch batch,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(batch);
        var requestBody = BuildRequestBody(batch);
        if (requestBody.Length > MaximumRequestBytes)
        {
            throw Invalid("SENSOR_LOOPBACK_REQUEST_SIZE_INVALID");
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(
            cancellationToken);
        timeout.CancelAfter(TimeSpan.FromMilliseconds(TimeoutMilliseconds));
        using var request = new HttpRequestMessage(HttpMethod.Post, DestinationUri)
        {
            Content = new ByteArrayContent(requestBody)
        };
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json")
        {
            CharSet = "utf-8"
        };

        using var response = await invoker.SendAsync(request, timeout.Token)
            .ConfigureAwait(false);
        if (response.StatusCode != HttpStatusCode.Accepted)
        {
            throw Invalid("SENSOR_LOOPBACK_RESPONSE_STATUS_INVALID");
        }
        if (
            response.Content.Headers.ContentType is not { } contentType ||
            !StringComparer.OrdinalIgnoreCase.Equals(
                contentType.MediaType,
                "application/json") ||
            !StringComparer.OrdinalIgnoreCase.Equals(contentType.CharSet, "utf-8"))
        {
            throw Invalid("SENSOR_LOOPBACK_RESPONSE_CONTENT_TYPE_INVALID");
        }
        if (response.Content.Headers.ContentLength > MaximumResponseBytes)
        {
            throw Invalid("SENSOR_LOOPBACK_RESPONSE_SIZE_INVALID");
        }

        var responseBody = await ReadBoundedAsync(response.Content, timeout.Token)
            .ConfigureAwait(false);
        try
        {
            return ParseReceipt(responseBody, batch);
        }
        catch (JsonException error)
        {
            throw new InvalidDataException("SENSOR_LOOPBACK_RECEIPT_INVALID", error);
        }
    }

    public void Dispose() => invoker.Dispose();

    private static byte[] BuildRequestBody(LocalSyntheticSignedBatch batch)
    {
        var core = NativeTelemetryFactBatch.ParseCore(batch.CanonicalPayload);
        core.ValidateContinuity(null);
        using var parsed = JsonDocument.Parse(batch.CanonicalPayload);
        var root = parsed.RootElement;
        if (
            batch.BatchSequence != 0 ||
            batch.PreviousBatchHash is not null ||
            !StringComparer.Ordinal.Equals(core.CanonicalPayload(), batch.CanonicalPayload) ||
            !StringComparer.Ordinal.Equals(core.BatchHash(), batch.BatchHash) ||
            root.GetProperty("provider").GetString() != "windows-scm" ||
            root.GetProperty("channel").GetString() != "system" ||
            root.GetProperty("eventFamily").GetString() != "service-change" ||
            root.GetProperty("facts").GetArrayLength() != 1)
        {
            throw Invalid("SENSOR_LOOPBACK_BATCH_INVALID");
        }

        if (batch.SignatureBase64.Length != 88)
        {
            throw Invalid("SENSOR_LOOPBACK_SIGNATURE_INVALID");
        }
        byte[] signature;
        try
        {
            signature = Convert.FromBase64String(batch.SignatureBase64);
        }
        catch (FormatException error)
        {
            throw new InvalidDataException("SENSOR_LOOPBACK_SIGNATURE_INVALID", error);
        }
        if (
            signature.Length != 64 ||
            !StringComparer.Ordinal.Equals(
                Convert.ToBase64String(signature),
                batch.SignatureBase64))
        {
            throw Invalid("SENSOR_LOOPBACK_SIGNATURE_INVALID");
        }

        using var output = new MemoryStream();
        using (var writer = new Utf8JsonWriter(output))
        {
            writer.WriteStartObject();
            foreach (var property in root.EnumerateObject())
            {
                property.WriteTo(writer);
            }
            writer.WriteString("batchHash", batch.BatchHash);
            writer.WriteString("signatureBase64", batch.SignatureBase64);
            writer.WriteEndObject();
        }
        return output.ToArray();
    }

    private static async Task<byte[]> ReadBoundedAsync(
        HttpContent content,
        CancellationToken cancellationToken)
    {
        await using var stream = await content.ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);
        var buffer = new byte[MaximumResponseBytes + 1];
        var total = 0;
        while (total < buffer.Length)
        {
            var read = await stream.ReadAsync(
                buffer.AsMemory(total, buffer.Length - total),
                cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }
            total += read;
        }
        if (total > MaximumResponseBytes)
        {
            throw Invalid("SENSOR_LOOPBACK_RESPONSE_SIZE_INVALID");
        }
        return buffer[..total];
    }

    private static LoopbackFactReceipt ParseReceipt(
        byte[] json,
        LocalSyntheticSignedBatch batch)
    {
        using var parsed = JsonDocument.Parse(
            json,
            new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 4
            });
        RequireExactProperties(
            parsed.RootElement,
            OuterReceiptFields,
            "SENSOR_LOOPBACK_RECEIPT_FIELDS_INVALID");
        var receipt = parsed.RootElement.GetProperty("receipt");
        RequireExactProperties(
            receipt,
            ReceiptFields,
            "SENSOR_LOOPBACK_RECEIPT_FIELDS_INVALID");
        if (
            receipt.GetProperty("schemaVersion").ValueKind != JsonValueKind.Number ||
            !receipt.GetProperty("schemaVersion").TryGetInt32(out var schemaVersion) ||
            receipt.GetProperty("status").ValueKind != JsonValueKind.String ||
            receipt.GetProperty("batchHash").ValueKind != JsonValueKind.String ||
            receipt.GetProperty("batchSequence").ValueKind != JsonValueKind.Number ||
            !receipt.GetProperty("batchSequence").TryGetInt64(out var sequence) ||
            receipt.GetProperty("factCount").ValueKind != JsonValueKind.Number ||
            !receipt.GetProperty("factCount").TryGetInt32(out var factCount) ||
            schemaVersion != 1 ||
            receipt.GetProperty("status").GetString() != "accepted" ||
            receipt.GetProperty("batchHash").GetString() != batch.BatchHash ||
            sequence != batch.BatchSequence ||
            factCount != 1)
        {
            throw Invalid("SENSOR_LOOPBACK_RECEIPT_INVALID");
        }
        return new LoopbackFactReceipt(
            schemaVersion,
            "accepted",
            batch.BatchHash,
            sequence,
            factCount);
    }

    private static void RequireExactProperties(
        JsonElement value,
        IReadOnlySet<string> expected,
        string error)
    {
        if (value.ValueKind != JsonValueKind.Object)
        {
            throw Invalid(error);
        }
        var supplied = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
        {
            if (!supplied.Add(property.Name))
            {
                throw Invalid(error);
            }
        }
        if (!supplied.SetEquals(expected))
        {
            throw Invalid(error);
        }
    }

    private static IReadOnlySet<string> ExactSet(params string[] values) =>
        values.ToHashSet(StringComparer.Ordinal);

    private static InvalidDataException Invalid(string code) => new(code);
}
