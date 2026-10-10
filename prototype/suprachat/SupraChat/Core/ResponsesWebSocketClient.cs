using System.Net.WebSockets;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json.Nodes;

namespace SupraChat.Core;

public sealed class ResponsesWebSocketClient : IAsyncDisposable
{
    public static readonly Uri Endpoint = new("wss://api.openai.com/v1/responses");

    private readonly ClientWebSocket _socket = new();
    private readonly SemaphoreSlim _sendGate = new(1, 1);

    public bool IsConnected => _socket.State == WebSocketState.Open;

    public static async Task<ResponsesWebSocketClient> ConnectAsync(
        string accessToken,
        CancellationToken cancellationToken = default)
    {
        var client = new ResponsesWebSocketClient();
        client._socket.Options.SetRequestHeader("Authorization", $"Bearer {accessToken}");
        await client._socket.ConnectAsync(Endpoint, cancellationToken).ConfigureAwait(false);
        return client;
    }

    public async Task SendRawAsync(
        string rawJson,
        string defaultModel,
        CancellationToken cancellationToken = default)
    {
        var json = NormalizeClientEvent(rawJson, defaultModel);
        var bytes = Encoding.UTF8.GetBytes(json);

        await _sendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_socket.State != WebSocketState.Open)
                throw new InvalidOperationException("Responses WebSocket is not connected.");

            await _socket.SendAsync(
                bytes,
                WebSocketMessageType.Text,
                endOfMessage: true,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _sendGate.Release();
        }
    }

    public async IAsyncEnumerable<string> ReadEventsAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var buffer = new byte[64 * 1024];

        while (_socket.State is WebSocketState.Open or WebSocketState.CloseSent)
        {
            using var message = new MemoryStream();
            WebSocketReceiveResult result;

            do
            {
                result = await _socket.ReceiveAsync(buffer, cancellationToken).ConfigureAwait(false);

                if (result.MessageType == WebSocketMessageType.Close)
                {
                    if (_socket.State == WebSocketState.CloseReceived)
                    {
                        await _socket.CloseOutputAsync(
                            WebSocketCloseStatus.NormalClosure,
                            "SupraChat acknowledged server close.",
                            CancellationToken.None).ConfigureAwait(false);
                    }
                    yield break;
                }

                if (result.MessageType != WebSocketMessageType.Text)
                    throw new InvalidOperationException(
                        $"Unexpected Responses WebSocket message type: {result.MessageType}.");

                message.Write(buffer, 0, result.Count);
            }
            while (!result.EndOfMessage);

            yield return Encoding.UTF8.GetString(message.GetBuffer(), 0, checked((int)message.Length));
        }
    }

    public static string NormalizeClientEvent(string rawJson, string defaultModel)
    {
        var root = JsonNode.Parse(rawJson) as JsonObject
            ?? throw new ArgumentException("Responses WebSocket event must be a JSON object.", nameof(rawJson));

        var type = root["type"]?.GetValue<string>();
        if (string.IsNullOrWhiteSpace(type))
            throw new ArgumentException("Responses WebSocket event must contain a type.", nameof(rawJson));

        if (string.Equals(type, "response.create", StringComparison.Ordinal))
        {
            if (!root.ContainsKey("model") || root["model"] is null)
                root["model"] = defaultModel;

            // ChatGPT-plan execution must remain non-persistent. WebSocket
            // transport does not use the HTTP-only stream/background fields.
            root["store"] = false;
            root.Remove("stream");
            root.Remove("background");
        }

        return root.ToJsonString(new System.Text.Json.JsonSerializerOptions
        {
            WriteIndented = true
        });
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            if (_socket.State == WebSocketState.Open)
            {
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
                await _socket.CloseAsync(
                    WebSocketCloseStatus.NormalClosure,
                    "SupraChat closing Responses WebSocket.",
                    timeout.Token).ConfigureAwait(false);
            }
        }
        catch
        {
            _socket.Abort();
        }
        finally
        {
            _socket.Dispose();
            _sendGate.Dispose();
        }
    }
}
