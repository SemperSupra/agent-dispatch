// Public-synthetic Go runtime and media-boundary contract fixture.
// Not a copy of, or validation of, a private application's source.
package publiccontract

import (
    "bytes"
    "crypto/sha256"
    "encoding/hex"
    "errors"
    "image"
    "image/color"
    "image/png"
    "net/url"
    "strconv"
    "strings"
    "testing"
)

// Example host and content are fictional; no network access is performed.
func normalizeSyntheticPost(raw string) (string, error) {
    u, err := url.Parse(raw)
    if err != nil || u == nil || u.Scheme != "https" || u.Host != "media.example.invalid" ||
        u.User != nil || u.Fragment != "" || u.RawPath != "" || u.Opaque != "" {
        return "", errors.New("UNTRUSTED_URL")
    }
    parts := strings.Split(strings.Trim(u.Path, "/"), "/")
    if len(parts) != 2 || parts[0] != "p" || len(parts[1]) < 4 || len(parts[1]) > 16 {
        return "", errors.New("UNTRUSTED_PATH")
    }
    for _, c := range parts[1] {
        if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
            return "", errors.New("UNTRUSTED_ID")
        }
    }
    if u.RawQuery != "" {
        p, err := url.ParseQuery(u.RawQuery)
        if err != nil || len(p) != 1 || len(p["ref"]) != 1 || p["ref"][0] != "public-fixture" {
            return "", errors.New("UNTRUSTED_QUERY")
        }
    }
    return "https://media.example.invalid/p/" + parts[1] + "/", nil
}

func validateSelection(raw []string, max int) ([]int, error) {
    if len(raw) == 0 || len(raw) > max || max > 20 { return nil, errors.New("BOUNDED_SELECTION_REQUIRED") }
    seen := map[int]bool{}
    out := make([]int, 0, len(raw))
    for _, x := range raw {
        n, err := strconv.Atoi(x)
        if err != nil || n < 1 || n > max || seen[n] { return nil, errors.New("INVALID_SELECTION") }
        seen[n] = true
        out = append(out, n)
    }
    return out, nil
}

func TestSyntheticURLBoundary(t *testing.T) {
    input := "https://media.example.invalid/p/Test_123/?ref=public-fixture"
    canonical, err := normalizeSyntheticPost(input)
    if err != nil || canonical != "https://media.example.invalid/p/Test_123/" { t.Fatalf("canonical %q %v", canonical, err) }
    rejected := []string{
        "http://media.example.invalid/p/Test_123/",
        "https://media.example.invalid.evil.invalid/p/Test_123/",
        "https://person@media.example.invalid/p/Test_123/",
        "https://media.example.invalid:443/p/Test_123/",
        "https://media.example.invalid/p/Test_123/?token=private",
        "https://media.example.invalid/p/Test_123/?ref=public-fixture&extra=yes",
        "https://media.example.invalid/p/Test_123/#secret",
        "https://media.example.invalid/p/../../admin/",
        "https://media.example.invalid/p/Bad%2fId/",
        "file:///etc/passwd",
    }
    for _, bad := range rejected { if got, err := normalizeSyntheticPost(bad); err == nil { t.Errorf("admitted unsafe %q as %q", bad, got) } }
}

func TestSyntheticSlideSelectionBoundaries(t *testing.T) {
    got, err := validateSelection([]string{"2", "1"}, 3)
    if err != nil || len(got) != 2 || got[0] != 2 || got[1] != 1 { t.Fatalf("selection %v %v", got, err) }
    for _, in := range [][]string{{}, {"0"}, {"4"}, {"1", "1"}, {"1garbage"}, {"1", ""}, {"-1"}} {
        if _, err := validateSelection(in, 3); err == nil { t.Errorf("admitted %q", in) }
    }
    if _, err := validateSelection([]string{"1"}, 21); err == nil { t.Fatal("unbounded inventory accepted") }
}

func TestSyntheticImageMustDecodeAndHash(t *testing.T) {
    img := image.NewRGBA(image.Rect(0, 0, 2, 2))
    img.Set(0, 0, color.RGBA{R: 7, G: 8, B: 9, A: 255})
    var buf bytes.Buffer
    if err := png.Encode(&buf, img); err != nil { t.Fatal(err) }
    cfg, format, err := image.DecodeConfig(bytes.NewReader(buf.Bytes()))
    if err != nil || format != "png" || cfg.Width != 2 || cfg.Height != 2 { t.Fatalf("metadata: %+v %s %v", cfg, format, err) }
    if _, _, err := image.Decode(bytes.NewReader(buf.Bytes())); err != nil { t.Fatal(err) }
    hash := sha256.Sum256(buf.Bytes())
    if len(hex.EncodeToString(hash[:])) != 64 { t.Fatal("digest length") }
    truncated := buf.Bytes()[:16]
    if _, _, err := image.Decode(bytes.NewReader(truncated)); err == nil { t.Fatal("truncated bytes falsely decoded") }
}
