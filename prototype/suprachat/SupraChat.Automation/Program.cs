using System.Text.Json;
using SupraChat.Core;

namespace SupraChat.Automation;

internal static class Program
{
    private const string Schema = "suprachat-machine/v1";
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower
    };

    public static async Task<int> Main(string[] args)
    {
        try
        {
            if (args.Length == 0 || args[0] is "-h" or "--help" or "help")
            {
                WriteJson(Help());
                return 0;
            }

            return args[0] switch
            {
                "capabilities" => WriteSuccess(Capabilities()),
                "doctor" => WriteSuccess(await DoctorAsync()),
                "auth-status" => WriteSuccess(await AuthStatusAsync()),
                "models" => WriteSuccess(await ModelsAsync()),
                "respond" => WriteSuccess(await RespondAsync(args[1..])),
                "responses-raw" => WriteSuccess(await RawResponsesAsync(args[1..])),
                "codex-rpc" => WriteSuccess(await CodexRpcAsync(args[1..])),
                "stdio" => await RunStdioAsync(),
                _ => WriteFailure(2, "USAGE", $"Unknown command: {args[0]}", Help())
            };
        }
        catch (MachineException ex)
        {
            return WriteFailure(ex.ExitCode, ex.Code, ex.Message);
        }
        catch (Exception ex)
        {
            return WriteFailure(4, "FAILED", SafeMessage(ex));
        }
    }

    private static object Help() => new
    {
        schema = Schema,
        product = "SupraChat",
        audience = new[] { "human", "automation", "agent" },
        commands = new object[]
        {
            new { name = "capabilities", description = "Read machine/product capability metadata." },
            new { name = "doctor", description = "Inspect local runtime/auth readiness without network calls." },
            new { name = "auth-status", description = "Read redacted local ChatGPT-plan authorization state." },
            new { name = "models", description = "List models visible to the saved ChatGPT-plan authorization." },
            new { name = "respond", description = "Run a typed streamed Responses request.", syntax = "respond --model <id> --input <text> [--web-search]" },
            new { name = "responses-raw", description = "Run an arbitrary SIWC Responses body.", syntax = "responses-raw --model <id> [--body <json>]; stdin is used when --body is omitted" },
            new { name = "codex-rpc", description = "Invoke a Codex app-server RPC.", syntax = "codex-rpc --method <name> [--params <json>]" },
            new { name = "stdio", description = "Serve line-delimited JSON-RPC 2.0 for agent clients." }
        },
        auth_boundary = "Interactive authorization is completed by a human through the GUI. Machine shells reuse the same protected local credential store."
    };

    private static object Capabilities() => new
    {
        schema = Schema,
        product = "SupraChat",
        platform = PlatformName(),
        audiences = new
        {
            human = new { ui = "desktop-gui", supported = true },
            automation = new { ui = "console-json", supported = true },
            agent = new { ui = "json-rpc-stdio", supported = true }
        },
        bindings = new[]
        {
            "chatgpt-product-web",
            "siwc-responses",
            "responses-websocket",
            "codex-app-server"
        },
        machine_methods = new[]
        {
            "capabilities/read",
            "doctor/read",
            "auth/status",
            "models/list",
            "responses/create",
            "responses/raw",
            "codex/request"
        },
        invariants = new
        {
            tokens_in_output = false,
            prompts_in_receipts = false,
            human_authorization_boundary = true,
            local_credentials_shared_with_gui = true,
            codex_runtime_resolution = "bundled-first"
        }
    };

    private static async Task<object> DoctorAsync()
    {
        var credential = await CredentialStore.TryLoadAsync();
        var registrations = await CredentialStore.ListRegistrationsAsync();
        var codex = CodexAppServer.ResolveExecutable();

        return new
        {
            schema = Schema,
            platform = PlatformName(),
            app_state_directory = AppState.DirectoryPath,
            auth = CredentialSummary(credential),
            registration_count = registrations.Count,
            codex = new
            {
                resolved_executable = codex,
                bundled = Path.IsPathRooted(codex) && File.Exists(codex)
            }
        };
    }

    private static async Task<object> AuthStatusAsync()
    {
        var credential = await CredentialStore.TryLoadAsync();
        return new
        {
            schema = Schema,
            auth = CredentialSummary(credential)
        };
    }

    private static async Task<object> ModelsAsync()
    {
        var credential = await RequireCredentialAsync();
        var models = await new ResponsesClient().ListModelsAsync(credential.AccessToken);
        return new
        {
            schema = Schema,
            binding = "siwc-responses",
            models = models.Select(x => new { id = x.Slug, display_name = x.DisplayName }).ToArray()
        };
    }

    private static async Task<object> RespondAsync(string[] args)
    {
        var model = RequiredOption(args, "--model");
        var input = RequiredOption(args, "--input");
        var webSearch = HasFlag(args, "--web-search");
        var credential = await RequireCredentialAsync();

        var result = await new ResponsesClient().StreamAsync(
            credential.AccessToken,
            model,
            input,
            attachments: null,
            enableWebSearch: webSearch);

        if (!result.Completed)
            throw new MachineException(4, "INCOMPLETE", "Responses stream ended without response.completed.");

        return new
        {
            schema = Schema,
            binding = "siwc-responses",
            completed = result.Completed,
            request_id = result.RequestId,
            event_types = result.EventTypes,
            output_text = result.Text
        };
    }

    private static async Task<object> RawResponsesAsync(string[] args)
    {
        var model = RequiredOption(args, "--model");
        var raw = Option(args, "--body");
        if (string.IsNullOrWhiteSpace(raw))
            raw = await Console.In.ReadToEndAsync();
        if (string.IsNullOrWhiteSpace(raw))
            throw new MachineException(2, "USAGE", "Provide --body <json> or JSON on stdin.");

        var credential = await RequireCredentialAsync();
        var result = await new ResponsesClient().StreamRawAsync(
            credential.AccessToken,
            model,
            raw);

        return new
        {
            schema = Schema,
            binding = "siwc-responses-raw",
            completed = result.Completed,
            request_id = result.RequestId,
            event_types = result.EventTypes,
            output_text = result.Text
        };
    }

    private static async Task<object> CodexRpcAsync(string[] args)
    {
        var method = RequiredOption(args, "--method");
        var rawParams = Option(args, "--params");
        var credential = await RequireCredentialAsync();

        JsonElement? parameters = null;
        if (!string.IsNullOrWhiteSpace(rawParams))
        {
            using var document = JsonDocument.Parse(rawParams);
            parameters = document.RootElement.Clone();
        }

        await using var client = await CodexAppServerClient.StartAsync(credential.AccessToken);
        var result = await client.RequestAsync(method, parameters);
        return new
        {
            schema = Schema,
            binding = "codex-app-server",
            method,
            result
        };
    }

    private static async Task<int> RunStdioAsync()
    {
        Console.Error.WriteLine("{\"suprachat\":\"stdio-ready\",\"schema\":\"suprachat-jsonrpc/v1\"}");

        string? line;
        while ((line = await Console.In.ReadLineAsync()) is not null)
        {
            if (string.IsNullOrWhiteSpace(line))
                continue;

            object response;
            try
            {
                using var document = JsonDocument.Parse(line);
                var root = document.RootElement;
                var id = root.TryGetProperty("id", out var idValue) ? idValue.Clone() : default(JsonElement?);
                var method = root.TryGetProperty("method", out var methodValue)
                    ? methodValue.GetString()
                    : null;
                var parameters = root.TryGetProperty("params", out var p) ? p.Clone() : default(JsonElement?);

                if (string.IsNullOrWhiteSpace(method))
                    throw new MachineException(2, "INVALID_REQUEST", "JSON-RPC method is required.");

                var result = await DispatchRpcAsync(method, parameters);
                response = new
                {
                    jsonrpc = "2.0",
                    id,
                    result
                };
            }
            catch (MachineException ex)
            {
                response = RpcError(line, -32000, ex.Code, ex.Message);
            }
            catch (JsonException ex)
            {
                response = RpcError(line, -32700, "PARSE_ERROR", ex.Message);
            }
            catch (Exception ex)
            {
                response = RpcError(line, -32001, "FAILED", SafeMessage(ex));
            }

            Console.Out.WriteLine(JsonSerializer.Serialize(response, JsonOptions));
            await Console.Out.FlushAsync();
        }

        return 0;
    }

    private static async Task<object> DispatchRpcAsync(string method, JsonElement? parameters)
    {
        return method switch
        {
            "capabilities/read" => Capabilities(),
            "doctor/read" => await DoctorAsync(),
            "auth/status" => await AuthStatusAsync(),
            "models/list" => await ModelsAsync(),
            "responses/create" => await RpcResponseCreateAsync(parameters),
            "responses/raw" => await RpcResponsesRawAsync(parameters),
            "codex/request" => await RpcCodexRequestAsync(parameters),
            _ => throw new MachineException(2, "METHOD_NOT_FOUND", $"Unsupported method: {method}")
        };
    }

    private static async Task<object> RpcResponseCreateAsync(JsonElement? parameters)
    {
        var p = RequireObject(parameters);
        var model = RequiredProperty(p, "model");
        var input = RequiredProperty(p, "input");
        var webSearch = p.TryGetProperty("web_search", out var ws) && ws.ValueKind == JsonValueKind.True;
        return await RespondAsync(new[]
        {
            "--model", model,
            "--input", input,
            ...(webSearch ? new[] { "--web-search" } : Array.Empty<string>())
        });
    }

    private static async Task<object> RpcResponsesRawAsync(JsonElement? parameters)
    {
        var p = RequireObject(parameters);
        var model = RequiredProperty(p, "model");
        if (!p.TryGetProperty("body", out var body))
            throw new MachineException(2, "INVALID_PARAMS", "responses/raw requires params.body.");

        return await RawResponsesAsync(new[]
        {
            "--model", model,
            "--body", body.GetRawText()
        });
    }

    private static async Task<object> RpcCodexRequestAsync(JsonElement? parameters)
    {
        var p = RequireObject(parameters);
        var method = RequiredProperty(p, "method");
        var args = new List<string> { "--method", method };
        if (p.TryGetProperty("params", out var rpcParams))
        {
            args.Add("--params");
            args.Add(rpcParams.GetRawText());
        }
        return await CodexRpcAsync(args.ToArray());
    }

    private static object RpcError(string line, int code, string type, string message)
    {
        JsonElement? id = null;
        try
        {
            using var doc = JsonDocument.Parse(line);
            if (doc.RootElement.TryGetProperty("id", out var value))
                id = value.Clone();
        }
        catch
        {
        }

        return new
        {
            jsonrpc = "2.0",
            id,
            error = new
            {
                code,
                message,
                data = new { type }
            }
        };
    }

    private static async Task<SiwcCredential> RequireCredentialAsync()
    {
        var credential = await CredentialStore.TryLoadAsync()
            ?? throw new MachineException(
                3,
                "AUTH_REQUIRED",
                "No local ChatGPT authorization is available. Complete Continue with ChatGPT in the SupraChat GUI first.");

        var refreshed = await new SiwcClient().RefreshIfNeededAsync(credential);
        if (!ReferenceEquals(refreshed, credential))
            await CredentialStore.SaveAsync(refreshed);

        if (!refreshed.HasPlanUsage)
            throw new MachineException(
                3,
                "PLAN_SCOPE_REQUIRED",
                $"Saved authorization does not include {SiwcProtocol.RequiredPlanScope}. Enable plan usage in the SupraChat GUI.");

        return refreshed;
    }

    private static object CredentialSummary(SiwcCredential? credential) =>
        credential is null
            ? new
            {
                present = false,
                plan_usage = false,
                expires_at = (DateTimeOffset?)null,
                scope_count = 0
            }
            : new
            {
                present = true,
                plan_usage = credential.HasPlanUsage,
                expires_at = credential.ExpiresAt,
                scope_count = credential.Scopes.Length
            };

    private static JsonElement RequireObject(JsonElement? element)
    {
        if (element is not { ValueKind: JsonValueKind.Object } value)
            throw new MachineException(2, "INVALID_PARAMS", "JSON-RPC params must be an object.");
        return value;
    }

    private static string RequiredProperty(JsonElement value, string name)
    {
        if (!value.TryGetProperty(name, out var property) ||
            property.ValueKind != JsonValueKind.String ||
            string.IsNullOrWhiteSpace(property.GetString()))
            throw new MachineException(2, "INVALID_PARAMS", $"Missing string params.{name}.");

        return property.GetString()!;
    }

    private static string RequiredOption(string[] args, string name) =>
        Option(args, name)
        ?? throw new MachineException(2, "USAGE", $"Missing required option {name}.");

    private static string? Option(string[] args, string name)
    {
        for (var i = 0; i < args.Length; i++)
        {
            if (!string.Equals(args[i], name, StringComparison.Ordinal))
                continue;
            if (i + 1 >= args.Length)
                throw new MachineException(2, "USAGE", $"Option {name} requires a value.");
            return args[i + 1];
        }
        return null;
    }

    private static bool HasFlag(string[] args, string name) =>
        args.Any(x => string.Equals(x, name, StringComparison.Ordinal));

    private static string PlatformName() =>
        OperatingSystem.IsWindows() ? "windows" :
        OperatingSystem.IsMacOS() ? "macos" :
        OperatingSystem.IsLinux() ? "linux" :
        "unknown";

    private static int WriteSuccess(object value)
    {
        WriteJson(new { ok = true, value });
        return 0;
    }

    private static int WriteFailure(int exitCode, string code, string message, object? detail = null)
    {
        WriteJson(new
        {
            ok = false,
            error = new { code, message, detail }
        });
        return exitCode;
    }

    private static void WriteJson(object value) =>
        Console.Out.WriteLine(JsonSerializer.Serialize(value, JsonOptions));

    private static string SafeMessage(Exception ex)
    {
        var message = ex.Message.Replace("\r", " ").Replace("\n", " ").Trim();
        return message.Length <= 1000 ? message : message[..1000] + "…";
    }

    private sealed class MachineException : Exception
    {
        public MachineException(int exitCode, string code, string message) : base(message)
        {
            ExitCode = exitCode;
            Code = code;
        }

        public int ExitCode { get; }
        public string Code { get; }
    }
}
