using System.Text.Json;
using Rudy.Evidence;

string request = JsonSerializer.Serialize(new { operation = "redact", document = new { text = "Türkçe 日本語", password = "synthetic" } });
Parallel.For(0, 1000, _ => {
    using var doc = JsonDocument.Parse(Evidence.Process(request));
    if (doc.RootElement.GetProperty("document").GetProperty("text").GetString() != "Türkçe 日本語" ||
        doc.RootElement.GetProperty("document").GetProperty("password").GetString() != "[REDACTED]") throw new Exception("C# roundtrip failed");
});
try { Evidence.Process("{bad"); throw new Exception("Invalid JSON accepted"); }
catch (ArgumentException) { }
Console.WriteLine("C# binding: 1,000 concurrent Unicode/redaction calls and error handling passed.");
