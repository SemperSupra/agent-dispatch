using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SupraChat.Core;

public sealed record QualificationReceipt(
    string Schema,
    DateTimeOffset RecordedAt,
    string Binding,
    string Model,
    string Runtime,
    string OperatingSystem,
    string AuthMode,
    string[] GrantedScopes,
    string SubjectPseudonym,
    bool Store,
    bool Stream,
    bool Completed,
    long ElapsedMilliseconds,
    int OutputCharacters,
    bool ContainsPrompt,
    bool ContainsOutput,
    bool ContainsTokenMaterial);

public static class QualificationReceipts
{
    public const string Schema = "suprachat-actor-interview-receipt/v1";

    public static QualificationReceipt BuildDirect(
        string model,
        SiwcCredential credential,
        bool completed,
        TimeSpan elapsed,
        int outputCharacters) =>
        Build(
            binding: "siwc-direct-responses",
            model: model,
            runtime: ".NET " + Environment.Version,
            credential: credential,
            completed: completed,
            elapsed: elapsed,
            outputCharacters: outputCharacters);

    public static QualificationReceipt BuildCodex(
        string model,
        SiwcCredential credential,
        bool completed,
        TimeSpan elapsed,
        int outputCharacters) =>
        Build(
            binding: "siwc-codex-app-server",
            model: model,
            runtime: "Codex app-server via SupraChat",
            credential: credential,
            completed: completed,
            elapsed: elapsed,
            outputCharacters: outputCharacters);

    public static QualificationReceipt Build(
        string binding,
        string model,
        string runtime,
        SiwcCredential credential,
        bool completed,
        TimeSpan elapsed,
        int outputCharacters) =>
        new(
            Schema,
            DateTimeOffset.UtcNow,
            binding,
            model,
            runtime,
            Environment.OSVersion.ToString(),
            "chatgpt-plan-oauth",
            credential.Scopes.OrderBy(x => x, StringComparer.Ordinal).ToArray(),
            Pseudonymize(credential.Subject),
            Store: false,
            Stream: true,
            Completed: completed,
            ElapsedMilliseconds: Math.Max(0, (long)elapsed.TotalMilliseconds),
            OutputCharacters: Math.Max(0, outputCharacters),
            ContainsPrompt: false,
            ContainsOutput: false,
            ContainsTokenMaterial: false);

    public static Task<string> WriteDirectAsync(
        string model,
        SiwcCredential credential,
        bool completed,
        TimeSpan elapsed,
        int outputCharacters) =>
        WriteAsync(BuildDirect(model, credential, completed, elapsed, outputCharacters));

    public static Task<string> WriteCodexAsync(
        string model,
        SiwcCredential credential,
        bool completed,
        TimeSpan elapsed,
        int outputCharacters) =>
        WriteAsync(BuildCodex(model, credential, completed, elapsed, outputCharacters));

    public static async Task<string> WriteAsync(QualificationReceipt receipt)
    {
        var directory = Path.Combine(AppState.DirectoryPath, "receipts");
        Directory.CreateDirectory(directory);

        var filename = $"{receipt.RecordedAt:yyyyMMddTHHmmssfffZ}-{Guid.NewGuid():N}.json";
        var path = Path.Combine(directory, filename);
        var temp = path + ".tmp";

        var json = JsonSerializer.Serialize(
            receipt,
            new JsonSerializerOptions { WriteIndented = true });

        await File.WriteAllTextAsync(temp, json + Environment.NewLine);
        AppState.TryRestrict(temp);
        File.Move(temp, path, overwrite: false);
        AppState.TryRestrict(path);
        return path;
    }

    private static string Pseudonymize(string subject)
    {
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(subject));
        return Convert.ToHexString(digest).ToLowerInvariant()[..16];
    }
}
