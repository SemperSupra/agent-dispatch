using System.Diagnostics;
using System.Globalization;
using System.IO.Compression;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;

namespace SupraChat.Core;

public sealed record DogfoodObservabilityDescriptor(
    string Schema,
    string RunId,
    string SessionId,
    string TraceId,
    string? SourceRevision,
    string? WorkflowRunId,
    string? RuntimeIdentifier,
    string Directory,
    string EventLog,
    string ReceiptDirectory,
    bool ContainsPrompts,
    bool ContainsOutputs,
    bool ContainsTokenMaterial,
    string PrivacyBoundary);

public sealed record DogfoodOperation(
    string Name,
    string CorrelationId,
    string TraceId,
    string SpanId,
    string? ParentSpanId,
    long StartedTimestamp);

public static class DogfoodObservability
{
    public const string Schema = "suprachat-dogfood-observability/v2";
    public const string EventSchema = "suprachat-dogfood-event/v2";

    private static readonly SemaphoreSlim Gate = new(1, 1);
    private static readonly string RunId = Guid.NewGuid().ToString("N");
    private static readonly PersistedInstallLink PersistedInstall = LoadPersistedInstallLink();
    private static readonly BuildProvenance Build = LoadBuildProvenance();
    private static readonly string SessionId =
        Environment.GetEnvironmentVariable("SUPRACHAT_DOGFOOD_SESSION_ID")
        ?? RunId;
    private static readonly string RootTraceId =
        NormalizeTraceId(Environment.GetEnvironmentVariable("SUPRACHAT_INSTALL_TRACE_ID"))
        ?? NormalizeTraceId(PersistedInstall.TraceId)
        ?? ActivityTraceId.CreateRandom().ToHexString();
    private static readonly string? InstallSessionId =
        EmptyToNull(Environment.GetEnvironmentVariable("SUPRACHAT_INSTALL_SESSION_ID"))
        ?? EmptyToNull(PersistedInstall.InstallSessionId);
    private static readonly long ProcessStartedTimestamp = Stopwatch.GetTimestamp();
    private static long _sequence;

    public static string DirectoryPath => Path.Combine(AppState.DirectoryPath, "diagnostics");
    public static string EventLogPath => Path.Combine(DirectoryPath, "events.jsonl");
    public static string ReceiptDirectory => Path.Combine(AppState.DirectoryPath, "receipts");

    public static DogfoodObservabilityDescriptor Describe() =>
        new(
            Schema,
            RunId,
            SessionId,
            RootTraceId,
            Build.SourceRevision,
            Build.WorkflowRunId,
            Build.RuntimeIdentifier,
            DirectoryPath,
            EventLogPath,
            ReceiptDirectory,
            ContainsPrompts: false,
            ContainsOutputs: false,
            ContainsTokenMaterial: false,
            PrivacyBoundary:
                "Structured dogfood diagnostics exclude prompts, model outputs, cookies, authorization codes, tokens, email addresses, raw account subjects, and WebView data.");

    public static DogfoodOperation BeginOperation(
        string name,
        string? correlationId = null,
        string? parentSpanId = null) =>
        new(
            name,
            correlationId ?? Guid.NewGuid().ToString("N"),
            RootTraceId,
            ActivitySpanId.CreateRandom().ToHexString(),
            parentSpanId,
            Stopwatch.GetTimestamp());

    public static Task RecordOperationAsync(
        string component,
        string @event,
        string outcome,
        DogfoodOperation operation,
        IReadOnlyDictionary<string, object?>? safeFields = null) =>
        RecordAsync(
            component,
            @event,
            outcome,
            operation.Name,
            operation.CorrelationId,
            operation.TraceId,
            operation.SpanId,
            operation.ParentSpanId,
            ElapsedMilliseconds(operation.StartedTimestamp),
            safeFields);

    public static Task RecordAsync(
        string component,
        string @event,
        string outcome,
        string? correlationId = null,
        IReadOnlyDictionary<string, object?>? safeFields = null) =>
        RecordAsync(
            component,
            @event,
            outcome,
            null,
            correlationId,
            RootTraceId,
            ActivitySpanId.CreateRandom().ToHexString(),
            null,
            null,
            safeFields);

    public static Task RecordExceptionAsync(
        string component,
        string @event,
        Exception exception,
        DogfoodOperation? operation = null,
        IReadOnlyDictionary<string, object?>? safeFields = null)
    {
        var fields = safeFields is null
            ? new Dictionary<string, object?>(StringComparer.Ordinal)
            : new Dictionary<string, object?>(safeFields, StringComparer.Ordinal);

        fields["exception_type"] = exception.GetType().FullName ?? exception.GetType().Name;
        fields["hresult"] = exception.HResult;
        if (exception is HttpRequestException http && http.StatusCode is { } status)
            fields["http_status"] = (int)status;

        return operation is null
            ? RecordAsync(component, @event, "failure", safeFields: fields)
            : RecordOperationAsync(component, @event, "failure", operation, fields);
    }

    public static async Task<string> ExportAsync(string outputPath)
    {
        outputPath = Path.GetFullPath(outputPath);
        var parent = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrWhiteSpace(parent))
            Directory.CreateDirectory(parent);

        if (File.Exists(outputPath))
            File.Delete(outputPath);

        await Gate.WaitAsync().ConfigureAwait(false);
        try
        {
            using var archive = ZipFile.Open(outputPath, ZipArchiveMode.Create);

            if (File.Exists(EventLogPath))
                archive.CreateEntryFromFile(EventLogPath, "diagnostics/events.jsonl", CompressionLevel.Optimal);

            var installerLog = Path.Combine(DirectoryPath, "installer-events.jsonl");
            if (File.Exists(installerLog))
                archive.CreateEntryFromFile(installerLog, "diagnostics/installer-events.jsonl", CompressionLevel.Optimal);

            var installReceipt = Path.Combine(DirectoryPath, "install-receipt.json");
            if (File.Exists(installReceipt))
                archive.CreateEntryFromFile(installReceipt, "diagnostics/install-receipt.json", CompressionLevel.Optimal);

            if (System.IO.Directory.Exists(ReceiptDirectory))
            {
                foreach (var receipt in System.IO.Directory.EnumerateFiles(ReceiptDirectory, "*.json"))
                {
                    archive.CreateEntryFromFile(
                        receipt,
                        "receipts/" + Path.GetFileName(receipt),
                        CompressionLevel.Optimal);
                }
            }

            var manifestEntry = archive.CreateEntry("manifest.json", CompressionLevel.Optimal);
            await using var stream = manifestEntry.Open();
            await JsonSerializer.SerializeAsync(
                stream,
                new
                {
                    schema = "suprachat-dogfood-diagnostics-export/v2",
                    exported_at_utc = UtcTimestamp(),
                    observability = Describe(),
                    includes = new[] { "structured diagnostics", "installer receipt", "redacted qualification receipts" },
                    excludes = new[]
                    {
                        "credentials",
                        "access tokens",
                        "refresh tokens",
                        "id tokens",
                        "authorization codes",
                        "cookies",
                        "WebView profile data",
                        "prompts",
                        "model output"
                    }
                },
                new JsonSerializerOptions { WriteIndented = true }).ConfigureAwait(false);
        }
        finally
        {
            Gate.Release();
        }

        AppState.TryRestrict(outputPath);
        return outputPath;
    }

    private static Task RecordAsync(
        string component,
        string @event,
        string outcome,
        string? operationName,
        string? correlationId,
        string traceId,
        string spanId,
        string? parentSpanId,
        long? durationMilliseconds,
        IReadOnlyDictionary<string, object?>? safeFields)
    {
        var fields = safeFields is null
            ? null
            : safeFields.ToDictionary(
                pair => pair.Key,
                pair => NormalizeSafeValue(pair.Key, pair.Value),
                StringComparer.Ordinal);

        var entry = new
        {
            schema = EventSchema,
            event_id = Guid.NewGuid().ToString("N"),
            timestamp_utc = UtcTimestamp(),
            run_id = RunId,
            session_id = SessionId,
            install_session_id = InstallSessionId,
            sequence = Interlocked.Increment(ref _sequence),
            process_id = Environment.ProcessId,
            component,
            @event,
            outcome,
            operation_name = operationName,
            correlation_id = correlationId,
            trace_id = traceId,
            span_id = spanId,
            traceparent = $"00-{traceId}-{spanId}-01",
            parent_span_id = parentSpanId,
            duration_ms = durationMilliseconds,
            process_elapsed_ms = ElapsedMilliseconds(ProcessStartedTimestamp),
            operating_system = Environment.OSVersion.ToString(),
            runtime = ".NET " + Environment.Version,
            application_version = Assembly.GetEntryAssembly()?.GetName().Version?.ToString() ?? "unknown",
            source_revision = Build.SourceRevision,
            workflow_run_id = Build.WorkflowRunId,
            runtime_identifier = Build.RuntimeIdentifier,
            fields
        };

        return AppendAsync(entry);
    }

    private static async Task AppendAsync(object entry)
    {
        await Gate.WaitAsync().ConfigureAwait(false);
        try
        {
            System.IO.Directory.CreateDirectory(DirectoryPath);
            RotateIfNeeded(EventLogPath);
            var json = JsonSerializer.Serialize(entry);
            await File.AppendAllTextAsync(EventLogPath, json + Environment.NewLine).ConfigureAwait(false);
            AppState.TryRestrict(EventLogPath);
        }
        catch
        {
            // Observability must never become an application dependency.
        }
        finally
        {
            Gate.Release();
        }
    }

    public static string UtcTimestamp() =>
        DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture);

    private static long ElapsedMilliseconds(long startedTimestamp) =>
        Math.Max(0, (long)Stopwatch.GetElapsedTime(startedTimestamp).TotalMilliseconds);

    private static BuildProvenance LoadBuildProvenance()
    {
        try
        {
            var path = Path.Combine(AppContext.BaseDirectory, "build-info.json");
            if (!File.Exists(path))
                return new(null, null, null);

            using var document = JsonDocument.Parse(File.ReadAllText(path));
            var root = document.RootElement;
            return new(
                root.TryGetProperty("source_revision", out var revision) ? revision.GetString() : null,
                root.TryGetProperty("workflow_run_id", out var run) ? run.GetString() : null,
                root.TryGetProperty("runtime_identifier", out var rid) ? rid.GetString() : null);
        }
        catch
        {
            return new(null, null, null);
        }
    }

    private sealed record BuildProvenance(
        string? SourceRevision,
        string? WorkflowRunId,
        string? RuntimeIdentifier);

    private static PersistedInstallLink LoadPersistedInstallLink()
    {
        try
        {
            var path = Path.Combine(
                AppState.DirectoryPath,
                "diagnostics",
                "install-receipt.json");
            if (!File.Exists(path))
                return new(null, null);

            using var document = JsonDocument.Parse(File.ReadAllText(path));
            var root = document.RootElement;
            return new(
                root.TryGetProperty("install_session_id", out var installSession)
                    ? installSession.GetString()
                    : null,
                root.TryGetProperty("trace_id", out var trace)
                    ? trace.GetString()
                    : null);
        }
        catch
        {
            return new(null, null);
        }
    }

    private sealed record PersistedInstallLink(
        string? InstallSessionId,
        string? TraceId);

    private static string? NormalizeTraceId(string? value)
    {
        var candidate = EmptyToNull(value)?.ToLowerInvariant();
        if (candidate is null || candidate.Length != 32 || candidate.Any(c => !Uri.IsHexDigit(c)) ||
            candidate.All(c => c == '0'))
            return null;
        return candidate;
    }

    private static string? EmptyToNull(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static object? NormalizeSafeValue(string key, object? value)
    {
        if (IsSensitiveField(key))
            return "<redacted>";

        return value switch
        {
            null => null,
            bool or byte or sbyte or short or ushort or int or uint or long or ulong or float or double or decimal => value,
            DateTimeOffset dto => dto.UtcDateTime.ToString("O", CultureInfo.InvariantCulture),
            DateTime dt => dt.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture),
            Guid guid => guid.ToString("D"),
            string text => NormalizeSafeString(text),
            _ => value.ToString() is { } text ? NormalizeSafeString(text) : null
        };
    }

    private static bool IsSensitiveField(string key)
    {
        var normalized = key.Replace("-", "_", StringComparison.Ordinal).ToLowerInvariant();
        return normalized is "access_token" or "refresh_token" or "id_token" or
               "authorization_code" or "password" or "secret" or "cookie" or
               "email" or "subject" or "prompt" or "output_text" or "response_text";
    }

    private static string NormalizeSafeString(string text)
    {
        if (text.Contains("Bearer ", StringComparison.OrdinalIgnoreCase))
            return "<redacted>";
        return text.Length <= 256 ? text : text[..256];
    }

    private static void RotateIfNeeded(string path)
    {
        const long maxBytes = 8L * 1024 * 1024;
        const int generations = 3;

        if (!File.Exists(path) || new FileInfo(path).Length < maxBytes)
            return;

        for (var generation = generations; generation >= 1; generation--)
        {
            var current = generation == 1 ? path : $"{path}.{generation - 1}";
            var next = $"{path}.{generation}";
            if (!File.Exists(current))
                continue;
            if (File.Exists(next))
                File.Delete(next);
            File.Move(current, next);
        }
    }
}
