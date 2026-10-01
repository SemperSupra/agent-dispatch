using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;

namespace SupraChat.Core;

public sealed record CodexProtocolEvent(
    string Kind,
    string? Id,
    string? Method,
    JsonElement Payload);

public sealed record CodexInterviewResult(
    bool Completed,
    string Status,
    string Text,
    string ThreadId,
    string TurnId,
    string Model,
    string ModelProvider);

public sealed class CodexRpcException : Exception
{
    public CodexRpcException(string method, int? code, string message)
        : base(code is null ? $"{method}: {message}" : $"{method} ({code}): {message}")
    {
        Method = method;
        Code = code;
    }

    public string Method { get; }
    public int? Code { get; }
}

public sealed class CodexAppServerClient : IAsyncDisposable
{
    private readonly Process _process;
    private readonly StreamWriter _stdin;
    private readonly StreamReader _stdout;
    private readonly CancellationTokenSource _lifetime = new();
    private readonly SemaphoreSlim _writeGate = new(1, 1);
    private readonly ConcurrentDictionary<string, PendingRequest> _pending = new();
    private readonly Channel<CodexProtocolEvent> _events = Channel.CreateUnbounded<CodexProtocolEvent>(
        new UnboundedChannelOptions { SingleReader = false, SingleWriter = true });
    private readonly ConcurrentDictionary<Guid, Channel<CodexProtocolEvent>> _subscribers = new();
    private readonly StringBuilder _stderr = new();
    private readonly Task _readerTask;
    private readonly Task _stderrTask;
    private bool _initialized;

    private sealed record PendingRequest(string Method, TaskCompletionSource<JsonElement> Completion);

    public sealed class CodexEventSubscription : IAsyncDisposable
    {
        private readonly CodexAppServerClient _owner;
        private readonly Guid _id;
        private int _disposed;

        internal CodexEventSubscription(
            CodexAppServerClient owner,
            Guid id,
            ChannelReader<CodexProtocolEvent> reader)
        {
            _owner = owner;
            _id = id;
            Reader = reader;
        }

        public ChannelReader<CodexProtocolEvent> Reader { get; }

        public ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
                _owner.RemoveSubscriber(_id);
            return ValueTask.CompletedTask;
        }
    }

    private CodexAppServerClient(Process process)
    {
        _process = process;
        _stdin = process.StandardInput;
        _stdout = process.StandardOutput;
        _readerTask = Task.Run(ReadLoopAsync);
        _stderrTask = Task.Run(DrainStderrAsync);
    }

    public int ProcessId => _process.Id;
    public bool IsRunning => !_process.HasExited;
    public ChannelReader<CodexProtocolEvent> Events => _events.Reader;

    public CodexEventSubscription SubscribeEvents()
    {
        var id = Guid.NewGuid();
        var channel = Channel.CreateUnbounded<CodexProtocolEvent>(
            new UnboundedChannelOptions { SingleReader = true, SingleWriter = true });
        if (!_subscribers.TryAdd(id, channel))
            throw new InvalidOperationException("Could not create Codex event subscription.");
        return new CodexEventSubscription(this, id, channel.Reader);
    }

    private void RemoveSubscriber(Guid id)
    {
        if (_subscribers.TryRemove(id, out var channel))
            channel.Writer.TryComplete();
    }

    public static JsonElement BuildInitializeParams(bool experimentalApi = true) =>
        JsonSerializer.SerializeToElement(new
        {
            clientInfo = new
            {
                name = "suprachat",
                title = "SupraChat",
                version = "0.1.0"
            },
            capabilities = new
            {
                experimentalApi
            }
        });

    public static JsonElement BuildThreadStartParams(string model, string workspace) =>
        JsonSerializer.SerializeToElement(new
        {
            model,
            modelProvider = "openai_chatgpt_plan",
            cwd = workspace,
            approvalPolicy = "never",
            sandbox = "read-only",
            ephemeral = true,
            developerInstructions =
                "This is an actor-qualification interview. Do not invoke tools, commands, files, network resources, MCP servers, apps, plugins, or external agents. Answer only from the supplied user input."
        });

    public static JsonElement BuildTurnStartParams(string threadId, string text) =>
        JsonSerializer.SerializeToElement(new
        {
            threadId,
            input = new[]
            {
                new
                {
                    type = "text",
                    text,
                    textElements = Array.Empty<object>()
                }
            }
        });

    public static async Task<CodexAppServerClient> StartAsync(
        string accessToken,
        CancellationToken cancellationToken = default)
    {
        var process = CodexAppServer.Start(accessToken);
        var client = new CodexAppServerClient(process);
        try
        {
            await client.InitializeAsync(cancellationToken).ConfigureAwait(false);
            return client;
        }
        catch
        {
            await client.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        if (_initialized)
            return;

        await RequestAsync("initialize", BuildInitializeParams(experimentalApi: true), cancellationToken)
            .ConfigureAwait(false);
        await NotifyAsync("initialized", null, cancellationToken).ConfigureAwait(false);
        _initialized = true;
    }

    public async Task<JsonElement> RequestAsync(
        string method,
        JsonElement? parameters = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfExited();

        var id = Guid.NewGuid().ToString("N");
        var completion = new TaskCompletionSource<JsonElement>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!_pending.TryAdd(id, new PendingRequest(method, completion)))
            throw new InvalidOperationException("Could not allocate Codex request id.");

        try
        {
            var message = new Dictionary<string, object?>
            {
                ["id"] = id,
                ["method"] = method
            };
            if (parameters is not null)
                message["params"] = parameters.Value;

            await WriteAsync(message, cancellationToken).ConfigureAwait(false);

            using var registration = cancellationToken.Register(
                () => completion.TrySetCanceled(cancellationToken));
            return await completion.Task.ConfigureAwait(false);
        }
        finally
        {
            _pending.TryRemove(id, out _);
        }
    }

    public async Task NotifyAsync(
        string method,
        JsonElement? parameters = null,
        CancellationToken cancellationToken = default)
    {
        ThrowIfExited();

        var message = new Dictionary<string, object?>
        {
            ["method"] = method
        };
        if (parameters is not null)
            message["params"] = parameters.Value;

        await WriteAsync(message, cancellationToken).ConfigureAwait(false);
    }

    public async Task RespondAsync(
        string requestId,
        JsonElement result,
        CancellationToken cancellationToken = default)
    {
        await WriteAsync(
            new Dictionary<string, object?>
            {
                ["id"] = requestId,
                ["result"] = result
            },
            cancellationToken).ConfigureAwait(false);
    }

    public async Task RespondErrorAsync(
        string requestId,
        int code,
        string message,
        CancellationToken cancellationToken = default)
    {
        await WriteAsync(
            new Dictionary<string, object?>
            {
                ["id"] = requestId,
                ["error"] = new { code, message }
            },
            cancellationToken).ConfigureAwait(false);
    }

    public async Task<CodexInterviewResult> RunTextInterviewAsync(
        string model,
        string prompt,
        Action<string>? onDelta = null,
        CancellationToken cancellationToken = default)
    {
        if (!_initialized)
            await InitializeAsync(cancellationToken).ConfigureAwait(false);

        await using var subscription = SubscribeEvents();

        var workspace = Path.Combine(
            AppState.DirectoryPath,
            "codex-interviews",
            Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(workspace);

        var threadResponse = await RequestAsync(
            "thread/start",
            BuildThreadStartParams(model, workspace),
            cancellationToken).ConfigureAwait(false);

        var thread = RequireProperty(threadResponse, "thread");
        var threadId = RequireString(thread, "id");
        var actualModel = TryString(threadResponse, "model") ?? model;
        var modelProvider = TryString(threadResponse, "modelProvider") ?? "openai_chatgpt_plan";

        var turnResponse = await RequestAsync(
            "turn/start",
            BuildTurnStartParams(threadId, prompt),
            cancellationToken).ConfigureAwait(false);

        var turn = RequireProperty(turnResponse, "turn");
        var turnId = RequireString(turn, "id");

        var output = new StringBuilder();
        var completedItems = new StringBuilder();
        string status = "unknown";

        while (true)
        {
            var evt = await subscription.Reader.ReadAsync(cancellationToken).ConfigureAwait(false);
            if (evt.Kind != "notification" || evt.Method is null)
                continue;

            var p = evt.Payload;
            var eventThreadId = TryString(p, "threadId");
            var eventTurnId = TryString(p, "turnId");

            if (evt.Method == "item/agentMessage/delta" &&
                eventThreadId == threadId &&
                eventTurnId == turnId)
            {
                var delta = TryString(p, "delta");
                if (!string.IsNullOrEmpty(delta))
                {
                    output.Append(delta);
                    onDelta?.Invoke(delta);
                }
                continue;
            }

            if (evt.Method == "item/completed" &&
                eventThreadId == threadId &&
                eventTurnId == turnId &&
                p.TryGetProperty("item", out var item) &&
                TryString(item, "type") == "agentMessage")
            {
                var completedText = TryString(item, "text");
                if (!string.IsNullOrEmpty(completedText))
                    completedItems.Append(completedText);
                continue;
            }

            if (evt.Method == "turn/completed" &&
                eventThreadId == threadId &&
                p.TryGetProperty("turn", out var completedTurn) &&
                TryString(completedTurn, "id") == turnId)
            {
                status = TryString(completedTurn, "status") ?? "unknown";
                break;
            }
        }

        var text = output.Length > 0 ? output.ToString() : completedItems.ToString();
        return new(
            Completed: string.Equals(status, "completed", StringComparison.OrdinalIgnoreCase),
            Status: status,
            Text: text,
            ThreadId: threadId,
            TurnId: turnId,
            Model: actualModel,
            ModelProvider: modelProvider);
    }

    private async Task ReadLoopAsync()
    {
        Exception? terminal = null;
        try
        {
            while (!_lifetime.IsCancellationRequested)
            {
                var line = await _stdout.ReadLineAsync(_lifetime.Token).ConfigureAwait(false);
                if (line is null)
                    break;
                if (string.IsNullOrWhiteSpace(line))
                    continue;

                using var doc = JsonDocument.Parse(line);
                var root = doc.RootElement.Clone();

                var id = TryId(root);
                var method = TryString(root, "method");

                if (id is not null && method is not null)
                {
                    var payload = root.TryGetProperty("params", out var serverParams)
                        ? serverParams.Clone()
                        : JsonSerializer.SerializeToElement(new { });
                    await PublishAsync(
                        new CodexProtocolEvent("server-request", id, method, payload),
                        _lifetime.Token).ConfigureAwait(false);
                    continue;
                }

                if (method is not null)
                {
                    var payload = root.TryGetProperty("params", out var notificationParams)
                        ? notificationParams.Clone()
                        : JsonSerializer.SerializeToElement(new { });
                    await PublishAsync(
                        new CodexProtocolEvent("notification", null, method, payload),
                        _lifetime.Token).ConfigureAwait(false);
                    continue;
                }

                if (id is not null && _pending.TryGetValue(id, out var pending))
                {
                    if (root.TryGetProperty("error", out var error))
                    {
                        var code = error.TryGetProperty("code", out var codeValue) && codeValue.TryGetInt32(out var parsed)
                            ? parsed
                            : (int?)null;
                        var message = TryString(error, "message") ?? "Codex app-server request failed.";
                        pending.Completion.TrySetException(new CodexRpcException(pending.Method, code, message));
                    }
                    else
                    {
                        var result = root.TryGetProperty("result", out var resultValue)
                            ? resultValue.Clone()
                            : JsonSerializer.SerializeToElement(new { });
                        pending.Completion.TrySetResult(result);
                    }
                }
            }
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
        {
        }
        catch (Exception ex)
        {
            terminal = ex;
        }
        finally
        {
            var exception = terminal ?? new EndOfStreamException(
                $"Codex app-server closed stdout. stderr={StderrTail()}");
            foreach (var item in _pending.Values)
                item.Completion.TrySetException(exception);
            _events.Writer.TryComplete(terminal);
            foreach (var subscriber in _subscribers.Values)
                subscriber.Writer.TryComplete(terminal);
        }
    }

    private async Task PublishAsync(CodexProtocolEvent evt, CancellationToken cancellationToken)
    {
        await _events.Writer.WriteAsync(evt, cancellationToken).ConfigureAwait(false);
        foreach (var subscriber in _subscribers.Values)
            subscriber.Writer.TryWrite(evt);
    }

    private async Task DrainStderrAsync()
    {
        try
        {
            while (!_lifetime.IsCancellationRequested)
            {
                var line = await _process.StandardError.ReadLineAsync(_lifetime.Token).ConfigureAwait(false);
                if (line is null)
                    break;

                lock (_stderr)
                {
                    _stderr.AppendLine(line);
                    if (_stderr.Length > 16000)
                        _stderr.Remove(0, _stderr.Length - 12000);
                }
            }
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
        {
        }
    }

    private async Task WriteAsync(object payload, CancellationToken cancellationToken)
    {
        var json = JsonSerializer.Serialize(payload);
        await _writeGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ThrowIfExited();
            await _stdin.WriteLineAsync(json.AsMemory(), cancellationToken).ConfigureAwait(false);
            await _stdin.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _writeGate.Release();
        }
    }

    private void ThrowIfExited()
    {
        if (_process.HasExited)
            throw new InvalidOperationException(
                $"Codex app-server exited with code {_process.ExitCode}. stderr={StderrTail()}");
    }

    private string StderrTail()
    {
        lock (_stderr)
        {
            var value = _stderr.ToString();
            return value.Length <= 2000 ? value : value[^2000..];
        }
    }

    private static JsonElement RequireProperty(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value)
            ? value
            : throw new InvalidOperationException($"Codex response omitted {name}.");

    private static string RequireString(JsonElement element, string name) =>
        TryString(element, name)
        ?? throw new InvalidOperationException($"Codex response omitted {name}.");

    private static string? TryString(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object &&
        element.TryGetProperty(name, out var value) &&
        value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static string? TryId(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Object ||
            !element.TryGetProperty("id", out var id))
            return null;

        return id.ValueKind switch
        {
            JsonValueKind.String => id.GetString(),
            JsonValueKind.Number => id.GetRawText(),
            _ => id.GetRawText()
        };
    }

    public async ValueTask DisposeAsync()
    {
        if (_lifetime.IsCancellationRequested)
            return;

        _lifetime.Cancel();
        try
        {
            _stdin.Close();
        }
        catch
        {
        }

        if (!_process.HasExited)
        {
            try
            {
                _process.Kill(entireProcessTree: true);
            }
            catch
            {
            }
        }

        try
        {
            await Task.WhenAll(_readerTask, _stderrTask).WaitAsync(TimeSpan.FromSeconds(2))
                .ConfigureAwait(false);
        }
        catch
        {
        }

        foreach (var id in _subscribers.Keys)
            RemoveSubscriber(id);

        _process.Dispose();
        _writeGate.Dispose();
        _lifetime.Dispose();
    }
}
