using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace SupraChat.Core;

public sealed record StreamedResponse(bool Completed, string Text);
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
        response.EnsureSuccessStatusCode();

        return ParseModels(await response.Content.ReadAsStringAsync());
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

    public async Task<StreamedResponse> StreamTextAsync(
        string accessToken,
        string model,
        string input,
        Action<string>? onDelta = null)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "responses");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Content = new StringContent(
            SiwcProtocol.BuildResponsesBody(model, input),
            Encoding.UTF8,
            "application/json");

        using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead);
        response.EnsureSuccessStatusCode();

        await using var stream = await response.Content.ReadAsStreamAsync();
        using var reader = new StreamReader(stream);
        var text = new StringBuilder();
        var completed = false;

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
                throw new InvalidOperationException("Responses stream reported response.failed.");
            }
        }

        return new(completed, text.ToString());
    }
}
