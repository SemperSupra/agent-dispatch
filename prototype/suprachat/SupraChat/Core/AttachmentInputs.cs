namespace SupraChat.Core;

public static class AttachmentInputs
{
    public const long MaxSingleBytes = 50L * 1024 * 1024;
    public const long MaxCombinedBytes = 50L * 1024 * 1024;

    public static async Task<IReadOnlyList<ResponseAttachment>> LoadPathsAsync(
        IEnumerable<string> paths,
        CancellationToken cancellationToken = default)
    {
        var attachments = new List<ResponseAttachment>();
        long total = 0;

        foreach (var raw in paths)
        {
            if (string.IsNullOrWhiteSpace(raw))
                continue;

            var path = Path.GetFullPath(raw);
            if (!File.Exists(path))
                throw new FileNotFoundException($"Attachment file not found: {path}", path);

            var info = new FileInfo(path);
            ValidateSize(info.Length, total + info.Length);
            total += info.Length;

            var bytes = await File.ReadAllBytesAsync(path, cancellationToken);
            attachments.Add(Create(Path.GetFileName(path), bytes));
        }

        return attachments;
    }

    public static ResponseAttachment Create(string name, ReadOnlySpan<byte> bytes)
    {
        ValidateSize(bytes.Length, bytes.Length);
        var mime = MimeTypeFor(name);
        var kind = IsImageMime(mime) ? "image" : "file";
        return new ResponseAttachment(kind, name, SiwcProtocol.ToDataUrl(mime, bytes), "auto");
    }

    public static string MimeTypeFor(string name) => Path.GetExtension(name).ToLowerInvariant() switch
    {
        ".png" => "image/png",
        ".jpg" or ".jpeg" => "image/jpeg",
        ".webp" => "image/webp",
        ".gif" => "image/gif",
        ".pdf" => "application/pdf",
        ".txt" => "text/plain",
        ".md" => "text/markdown",
        ".json" => "application/json",
        ".csv" => "text/csv",
        ".tsv" => "text/tab-separated-values",
        ".html" or ".htm" => "text/html",
        ".xml" => "application/xml",
        ".rtf" => "application/rtf",
        ".odt" => "application/vnd.oasis.opendocument.text",
        ".doc" => "application/msword",
        ".docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".ppt" => "application/vnd.ms-powerpoint",
        ".pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ".xls" => "application/vnd.ms-excel",
        ".xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        _ => "application/octet-stream"
    };

    public static bool IsImageMime(string mime) =>
        mime is "image/png" or "image/jpeg" or "image/webp" or "image/gif";

    public static long EstimateDataUrlBytes(string value)
    {
        var comma = value.IndexOf(',');
        if (comma < 0)
            return 0;
        var base64Length = value.Length - comma - 1;
        return base64Length * 3L / 4L;
    }

    public static void ValidateSize(long singleBytes, long combinedBytes)
    {
        if (singleBytes >= MaxSingleBytes || combinedBytes > MaxCombinedBytes)
            throw new InvalidOperationException(
                "Responses file inputs require each file to be under 50 MB and all files combined to be at most 50 MB.");
    }
}
