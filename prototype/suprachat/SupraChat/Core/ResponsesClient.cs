using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SupraChat.Core;

public sealed record StreamedResponse(
    bool Completed,
    string Text,
    IReadOnlyList<string> EventTypes,
    string? RequestId);

public sealed record ModelChoice(string Slug, string DisplayName)
{
    public override string ToString() => DisplayName;
}

public sealed class ResponsesClient
{
    private readonly HttpClient _http = new() { BaseAddress = new Uri("https://api.openai.com/v1/") };

    public async Task<IReadOnlyList<ModelChoice>> ListModelsAsync(string accessToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "models");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        using var response = await _http.SendAsync(request);
        var json = await response.Content.ReadAsStringAsync();
        if (!response.IsSuccessStatusCode)
            throw BuildHttpFailure("model listing", response, json);

        return ParseModels(json);
    }

    public static IReadOnlyList<ModelChoice> ParseModels(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        var output = new List<ModelChoice>();

        if (root.TryGetProperty("models", out var models) && models.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in models.EnumerateArray())
            {
                if (item.TryGetProperty("visibility", out var visibility) &&
                    !string.Equals(visibility.GetString(), "list", StringComparison.Ordinal))
                    continue;

                var slug = item.TryGetProperty("slug", out var s) ? s.GetString() : null;
                var displayName = item.TryGetProperty("display_name", out var d) ? d.GetString() : null;
                if (!string.IsNullOrWhiteSpace(slug))
                    output.Add(new ModelChoice(slug, string.IsNullOrWhiteSpace(displayName) ? slug : displayName!));
            }
            return output;
        }

        if (root.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in data.EnumerateArray())
            {
                var id = item.TryGetProperty("id", out var i) ? i.GetString() : null;
                if (!string.IsNullOrWhiteSpace(id))
                    output.Add(new ModelChoice(id, id));
            }
        }

        return output;
    }

    public async Task<StreamedResponse> StreamAsync(
        string accessToken,
        string model,
        string input,
        IEnumerable<ResponseAttachment>? attachments = null,
        bool enableWebSearch = false,
        Action<string>? onDelta = null) =>
        await SendStreamAsync(
            accessToken,
            SiwcProtocol.BuildResponsesBody(model, input, attachments, enableWebSearch),
            onDelta,
            onEvent: null).ConfigureAwait(false);

    public Task<StreamedResponse> StreamTextAsync(
        string accessToken,
        string model,
        string input,
        Action<string>? onDelta = null) =>
        StreamAsync(accessToken, model, input, null, false, onDelta);

    public Task<StreamedResponse> StreamRawAsync(
        string accessToken,
        string defaultModel,
        string rawJson,
        Action<string>? onDelta = null,
        Action<string, string>? onEvent = null) =>
        SendStreamAsync(
            accessToken,
            NormalizeRawResponsesBody(rawJson, defaultModel),
            onDelta,
            onEvent);

    public static string NormalizeRawResponsesBody(string rawJson, string defaultModel)
    {
        var root = JsonNode.Parse(rawJson) as JsonObject
            ?? throw new ArgumentException("Raw Responses body must be a JSON object.", nameof(rawJson));

        if (!root.ContainsKey("model") || root["model"] is null)
            root["model"] = defaultModel;

        // Current ChatGPT-plan sharing contract requires these exact values.
        root["store"] = false;
        root["stream"] = true;

        return root.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
    }

    private async Task<StreamedResponse> SendStreamAsync(
        string accessToken,
        string body,
        Action<string>? onDelta,
        Action<string, string>? onEvent)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "responses");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Content = new StringContent(body, Encoding.UTF8, "application/json");

        using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
        var requestId = response.Headers.TryGetValues("x-request-id", out var ids)
            ? ids.FirstOrDefault()
            : null;

        if (!response.IsSuccessStatusCode)
        {
            var responseBody = await response.Content.ReadAsStringAsync();
            throw BuildHttpFailure("Responses request", response, responseBody);
        }

        await using var stream = await response.Content.ReadAsStreamAsync();
        using var reader = new StreamReader(stream);
        var text = new StringBuilder();
        var completed = false;
        var eventTypes = new HashSet<string>(StringComparer.Ordinal);

        while (await reader.ReadLineAsync() is { } line)
        {
            if (!line.StartsWith("data:", StringComparison.Ordinal))
                continue;

            var payload = line[5..].Trim();
            if (payload.Length == 0 || payload == "[DONE]")
                continue;

            using var doc = JsonDocument.Parse(payload);
            var root = doc.RootElement;
            var type = root.TryGetProperty("type", out var t) ? t.GetString() : null;
            if (!string.IsNullOrWhiteSpace(type))
            {
                eventTypes.Add(type);
                onEvent?.Invoke(type, payload);
            }

            if (type == "response.output_text.delta" && root.TryGetProperty("delta", out var d))
            {
                var delta = d.GetString() ?? "";
                text.Append(delta);
                onDelta?.Invoke(delta);
            }
            else if (type == "response.completed")
            {
                completed = true;
            }
            else if (type == "response.failed")
            {
                throw new InvalidOperationException(
                    "Responses stream reported response.failed." +
                    ExtractResponseError(root) +
                    $" request_id={requestId ?? "unknown"}");
            }
            else if (type == "response.incomplete")
            {
                throw new InvalidOperationException(
                    "Responses stream reported response.incomplete." +
                    $" request_id={requestId ?? "unknown"}");
            }
        }

        return new(
            completed,
            text.ToString(),
            eventTypes.OrderBy(x => x, StringComparer.Ordinal).ToArray(),
            requestId);
    }

    private static Exception BuildHttpFailure(
        string operation,
        HttpResponseMessage response,
        string body)
    {
        var requestId = response.Headers.TryGetValues("x-request-id", out var ids)
            ? ids.FirstOrDefault()
            : null;
        var compact = body.Replace("\r", " ").Replace("\n", " ").Trim();
        if (compact.Length > 1000)
            compact = compact[..1000] + "…";
        return new InvalidOperationException(
            $"{operation} failed ({(int)response.StatusCode}) request_id={requestId ?? "unknown"} body={compact}");
    }

    private static string ExtractResponseError(JsonElement root)
    {
        if (!root.TryGetProperty("response", out var response) ||
            !response.TryGetProperty("error", out var error))
            return "";

        var code = error.TryGetProperty("code", out var c) ? c.GetString() : null;
        var param = error.TryGetProperty("param", out var p) ? p.GetString() : null;
        return $" code={code ?? "unknown"} param={param ?? "none"}";
    }
}
