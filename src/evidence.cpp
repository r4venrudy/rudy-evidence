#include "rudy/evidence.hpp"
#include <nlohmann/json.hpp>
#include "blake3.h"
#include <algorithm>
#include <array>
#include <cctype>
#include <map>
#include <set>
#include <vector>

namespace rudy::evidence {
namespace {
using J = nlohmann::json;
constexpr std::size_t max_findings = 10000;
constexpr std::size_t max_text = 65536;
constexpr std::string_view schema = "rudy-evidence/v1";
[[noreturn]] void fail(const char *message) { throw Error(message); }
void require(bool condition, const char *message) { if (!condition) fail(message); }
std::string lower(std::string text) {
    for (auto& c : text) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A'));
    return text;
}
std::string text(const J& object, const char *key, bool required = true, const char *fallback = "") {
    if (!object.contains(key)) { if (required) fail("Required text field is missing"); return fallback; }
    require(object[key].is_string(), "Expected a text field");
    auto value = object[key].get<std::string>();
    require(value.size() <= max_text && (!required || !value.empty()), "Text field is empty or exceeds 64 KiB");
    return value;
}
std::string digest(std::string_view data) {
    blake3_hasher h; blake3_hasher_init(&h); blake3_hasher_update(&h, data.data(), data.size());
    std::array<unsigned char, BLAKE3_OUT_LEN> bytes{}; blake3_hasher_finalize(&h, bytes.data(), bytes.size());
    constexpr char hex[] = "0123456789abcdef";
    std::string output = "blake3:";
    for (auto b : bytes) { output += hex[b >> 4]; output += hex[b & 15]; }
    return output;
}
J parse(std::string_view input) {
    require(input.size() <= max_input_bytes, "Input exceeds 16 MiB");
    require(input.find('\0') == std::string_view::npos, "NUL byte in JSON input");
    std::vector<std::set<std::string>> keys;
    std::size_t nodes = 0;
    return J::parse(input, [&](int depth, J::parse_event_t event, J& value) {
        require(depth <= 32 && ++nodes <= 500000, "JSON depth or node limit exceeded");
        if (event == J::parse_event_t::object_start) keys.emplace_back();
        else if (event == J::parse_event_t::object_end) keys.pop_back();
        else if (event == J::parse_event_t::key) {
            auto key = value.get<std::string>();
            require(key.size() <= 256, "JSON key exceeds 256 bytes");
            require(keys.back().insert(key).second, "Duplicate JSON object key");
        } else if (event == J::parse_event_t::value && value.is_string())
            require(value.get_ref<const std::string&>().size() <= max_input_bytes, "JSON string exceeds 16 MiB");
        return true;
    });
}
const std::set<std::string> sensitive_keys{
    "password", "passwd", "secret", "client_secret", "api_key", "apikey", "token", "access_token",
    "refresh_token", "authorization", "proxy-authorization", "cookie", "set-cookie", "private_key"
};
bool space(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f'; }
bool boundary(char c) { return !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'); }
bool stop(char c) { return space(c) || std::string_view("\"'&,;<>}]").find(c) != std::string_view::npos; }
std::string redact_text(const std::string& input, std::size_t& count) {
    auto folded = lower(input);
    std::string output;
    for (std::size_t i = 0; i < input.size();) {
        if (input.compare(i, 3, "://") == 0) {
            auto end = i + 3;
            while (end < input.size() && !stop(input[end]) && input[end] != '/' && input[end] != '?' && input[end] != '#') ++end;
            auto at = input.find('@', i + 3);
            if (at != std::string::npos && at < end && input.substr(i + 3, at - i - 3) != "[REDACTED]") {
                output += "://[REDACTED]@"; ++count; i = at + 1; continue;
            }
        }
        std::size_t start = i, end = i;
        bool matched = false;
        if (i == 0 || boundary(input[i - 1])) {
            if (folded.compare(i, 7, "bearer ") == 0) { start = i + 7; matched = true; }
            if (folded.compare(i, 6, "basic ") == 0) { start = i + 6; matched = true; }
            // GitHub, GitLab, Slack, Stripe secret/restricted and npm tokens all start with a fixed prefix
            for (std::string_view prefix : {"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-",
                                            "xoxb-", "xoxp-", "xoxa-", "xoxs-", "sk_live_", "rk_live_", "npm_"})
                if (input.compare(i, prefix.size(), prefix) == 0) { start = i; matched = true; }
            for (std::string_view key : {"password", "passwd", "secret", "api_key", "apikey", "token", "access_token", "client_secret"}) {
                if (folded.compare(i, key.size(), key) != 0) continue;
                auto p = i + key.size();
                if (p < input.size() && (input[p] == '=' || input[p] == ':')) {
                    ++p;
                    while (p < input.size() && (input[p] == ' ' || input[p] == '\t')) ++p;
                    if (p < input.size() && (input[p] == '\'' || input[p] == '"')) ++p;
                    start = p; matched = true; break;
                }
            }
        }
        if (matched) {
            end = start;
            while (end < input.size() && !stop(input[end])) ++end;
            if (end > start && input.compare(start, 10, "[REDACTED]") != 0) {
                output.append(input, i, start - i); output += "[REDACTED]"; ++count; i = end; continue;
            }
        }
        output += input[i++];
    }
    return output;
}
void redact(J& value, std::size_t& count) {
    if (value.is_object()) for (auto it = value.begin(); it != value.end(); ++it) {
        if (sensitive_keys.contains(lower(it.key())) && !it.value().is_null()) {
            if (it.value() != "[REDACTED]") { it.value() = "[REDACTED]"; ++count; }
        } else redact(it.value(), count);
    }
    else if (value.is_array()) for (auto& child : value) redact(child, count);
    else if (value.is_string()) value = redact_text(value.get_ref<const std::string&>(), count);
}
int rank(const std::string& severity) {
    static const std::vector<std::string> levels{"info", "low", "medium", "high", "critical"};
    auto it = std::find(levels.begin(), levels.end(), severity);
    require(it != levels.end(), "Unsupported severity");
    return static_cast<int>(it - levels.begin());
}
J strings(J value) {
    if (value.is_string()) value = J::array({value});
    require(value.is_array() && value.size() <= 256, "Text array exceeds limit");
    std::set<std::string> sorted;
    for (const auto& v : value) {
        require(v.is_string() && v.get_ref<const std::string&>().size() <= max_text, "Invalid text array item");
        sorted.insert(v.get<std::string>());
    }
    require(sorted.size() <= 128, "Text array exceeds 128 unique strings");
    return sorted;
}
J finding(const J& input) {
    require(input.is_object(), "Finding must be an object");
    static const std::set<std::string> fields{"scope", "producer", "rule_id", "title", "severity", "asset", "location", "evidence", "identifiers", "fingerprint"};
    for (auto it = input.begin(); it != input.end(); ++it) require(fields.contains(it.key()), "Unknown native finding field");
    J f{{"scope", text(input, "scope")}, {"producer", text(input, "producer")}, {"rule_id", text(input, "rule_id")},
        {"title", text(input, "title")}, {"severity", lower(text(input, "severity"))}};
    rank(f["severity"]);
    const auto& asset = input.at("asset");
    require(asset.is_object() && asset.size() == 2, "Asset must contain kind and id");
    auto kind = text(asset, "kind");
    require(std::set<std::string>{"url", "host", "file", "package", "process", "other"}.contains(kind), "Unsupported asset kind");
    f["asset"] = {{"kind", kind}, {"id", text(asset, "id")}};
    f["location"] = J::object();
    if (input.contains("location")) {
        const auto& loc = input["location"];
        require(loc.is_object() && loc.size() <= 3, "Invalid location");
        for (auto it = loc.begin(); it != loc.end(); ++it) {
            require(it.key() == "path" || it.key() == "line" || it.key() == "column", "Unknown location field");
            if (it.key() == "path") f["location"]["path"] = text(loc, "path");
            else {
                require(it.value().is_number_integer() && it.value() > 0 && it.value() <= 2147483647, "Location coordinates must be positive 32-bit integers");
                f["location"][it.key()] = it.value();
            }
        }
    }
    f["evidence"] = strings(input.value("evidence", J::array()));
    f["identifiers"] = strings(input.value("identifiers", J::array()));
    J identity = J::array({"rudy-finding/v1", f["scope"], f["producer"], f["rule_id"], f["asset"], f["location"]});
    f["fingerprint"] = digest(identity.dump());
    if (input.contains("fingerprint")) require(input["fingerprint"] == f["fingerprint"], "Finding fingerprint mismatch");
    return f;
}
J sorted_unique(J input) {
    std::map<std::string, J> entries;
    for (auto& v : input) { auto key = v.dump(); entries.emplace(std::move(key), std::move(v)); }
    J result = J::array(); for (auto& [key, v] : entries) { (void)key; result.push_back(std::move(v)); }
    return result;
}
J compact(const J& input) {
    require(input.is_array() && input.size() <= max_findings, "Finding count exceeds 10000");
    std::map<std::string, J> entries;
    for (const auto& v : input) {
        auto f = finding(v); auto id = f["fingerprint"].get<std::string>();
        auto [it, inserted] = entries.emplace(id, f);
        if (!inserted) {
            auto& old = it->second;
            if (rank(f["severity"]) > rank(old["severity"])) old["severity"] = f["severity"];
            if (f["title"].get<std::string>() < old["title"].get<std::string>()) old["title"] = f["title"];
            for (const char *key : {"evidence", "identifiers"}) {
                for (const auto& item : f[key]) old[key].push_back(item);
                old[key] = strings(old[key]);
            }
        }
    }
    J result = J::array(); for (auto& [id, f] : entries) { (void)id; result.push_back(std::move(f)); }
    return result;
}
J seal(J value) {
    value.erase("integrity"); value["integrity"] = {{"algorithm", "blake3-256"}, {"digest", digest(value.dump())}};
    return value;
}
J bundle(J findings, J sources, std::size_t replacements) {
    auto items = compact(findings);
    J counts{{"info", 0}, {"low", 0}, {"medium", 0}, {"high", 0}, {"critical", 0}};
    for (const auto& f : items) counts[f["severity"].get<std::string>()] = counts[f["severity"].get<std::string>()].get<int>() + 1;
    return seal({{"schema", schema}, {"findings", items}, {"sources", sorted_unique(sources)},
        {"summary", {{"findings", items.size()}, {"severity", counts}}},
        {"redaction", {{"policy", "builtin-v1"}, {"replacements", replacements}}}});
}
J validate(const J& input) {
    require(input.is_object() && input.size() == 6 && input.value("schema", "") == schema, "Unsupported evidence bundle");
    require(input.contains("integrity") && input["integrity"].is_object(), "Missing bundle integrity");
    auto supplied = input["integrity"];
    require(seal(input)["integrity"] == supplied, "Bundle integrity mismatch");
    require(input["sources"].is_array() && input["sources"].size() <= 128, "Invalid source list");
    for (const auto& source : input["sources"]) {
        require(source.is_object() && source.size() == 3, "Invalid source descriptor");
        text(source, "format"); text(source, "scope"); auto hash = text(source, "digest");
        require(hash.starts_with("blake3:") && hash.size() == 71 && std::all_of(hash.begin() + 7, hash.end(), [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }), "Invalid source digest");
    }
    const auto& privacy = input["redaction"];
    require(privacy.is_object() && privacy.size() == 2 && privacy.value("policy", "") == "builtin-v1" && privacy.at("replacements").is_number_unsigned(), "Invalid redaction metadata");
    require(privacy["replacements"] <= max_input_bytes, "Redaction count exceeds limit");
    auto sanitized = J::array({input.at("findings"), input.at("sources")}); std::size_t remaining = 0; redact(sanitized, remaining);
    require(remaining == 0, "Bundle violates builtin redaction policy");
    auto rebuilt = bundle(input.at("findings"), input["sources"], privacy["replacements"].get<std::size_t>());
    require(rebuilt == input, "Bundle is not canonical or has inconsistent metadata");
    return input;
}
J base(const std::string& producer, const std::string& rule, const std::string& title, const std::string& severity,
       const std::string& kind, const std::string& asset, J evidence = J::array()) {
    return {{"producer", producer}, {"rule_id", rule}, {"title", title}, {"severity", severity},
        {"asset", {{"kind", kind}, {"id", asset}}}, {"evidence", evidence}};
}
J normalize(const std::string& format, std::string scope, J doc, std::string_view raw) {
    std::size_t replacements = 0; scope = redact_text(scope, replacements); redact(doc, replacements);
    J found = J::array();
    auto add = [&](J value) { require(found.size() < max_findings, "Finding count exceeds 10000"); if (!value.contains("scope")) value["scope"] = scope; found.push_back(std::move(value)); };
    if (format == "native") {
        require(doc.is_object() && doc.size() == 1 && doc.contains("findings") && doc["findings"].is_array(), "Native input must contain only findings array");
        for (const auto& f : doc["findings"]) add(f);
    } else if (format == "semgrep") {
        require(doc.is_object() && doc.contains("results") && doc["results"].is_array(), "Missing Semgrep results");
        for (const auto& r : doc["results"]) {
            const auto& extra = r.at("extra"); auto s = lower(text(extra, "severity"));
            if (s == "error") s = "high"; else if (s == "warning") s = "medium";
            auto path = text(r, "path"); auto f = base("semgrep", text(r, "check_id"), text(extra, "message"), s, "file", path);
            f["location"] = {{"path", path}, {"line", r.at("start").at("line")}};
            if (extra.contains("metadata") && extra["metadata"].contains("cwe")) f["identifiers"] = strings(extra["metadata"]["cwe"]);
            add(std::move(f));
        }
    } else if (format == "nuclei") {
        if (doc.is_object()) doc = J::array({doc});
        require(doc.is_array(), "Nuclei input must be an object or array");
        for (const auto& r : doc) {
            const auto& info = r.at("info");
            auto f = base("nuclei", text(r, "template-id"), text(info, "name"), lower(text(info, "severity")), "url", text(r, "matched-at"));
            if (r.contains("matcher-name")) f["evidence"] = J::array({text(r, "matcher-name")});
            add(std::move(f));
        }
    } else if (format == "trivy") {
        require(doc.is_object() && doc.contains("Results") && doc["Results"].is_array(), "Missing Trivy Results");
        for (const auto& group : doc["Results"]) {
            auto target = text(group, "Target");
            if (!group.contains("Vulnerabilities") || group["Vulnerabilities"].is_null()) continue;
            require(group["Vulnerabilities"].is_array(), "Invalid Trivy vulnerability list");
            for (const auto& v : group["Vulnerabilities"]) {
                auto id = text(v, "VulnerabilityID"); auto pkg = text(v, "PkgName") + "@" + text(v, "InstalledVersion");
                auto f = base("trivy", id, text(v, "Title", false, "Package vulnerability"), lower(text(v, "Severity")), "package", target + "::" + pkg);
                f["location"] = {{"path", target}}; f["identifiers"] = J::array({id});
                if (v.contains("FixedVersion")) f["evidence"] = J::array({"Fixed version: " + text(v, "FixedVersion", false)});
                add(std::move(f));
            }
        }
    } else if (format == "sarif") {
        require(doc.is_object() && doc.value("version", "") == "2.1.0" && doc.contains("runs") && doc["runs"].is_array(), "Expected SARIF 2.1.0 runs");
        for (const auto& run : doc["runs"]) {
            auto producer = text(run.at("tool").at("driver"), "name");
            if (!run.contains("results")) continue;
            require(run["results"].is_array(), "Invalid SARIF results");
            for (const auto& r : run["results"]) {
                auto level = text(r, "level", false, "warning");
                require(level == "error" || level == "warning" || level == "note" || level == "none", "Unsupported SARIF level");
                std::string severity = level == "error" ? "high" : level == "warning" ? "medium" : "info";
                if (r.contains("properties") && r["properties"].contains("rudySeverity")) severity = text(r["properties"], "rudySeverity");
                auto f = base(producer, text(r, "ruleId"), text(r.at("message"), "text"), severity, "other", "unlocated");
                if (r.contains("locations") && !r["locations"].empty()) {
                    require(r["locations"].is_array() && r["locations"].size() == 1, "SARIF subset supports one physical location");
                    const auto& loc = r["locations"][0].at("physicalLocation");
                    const auto& artifact = loc.at("artifactLocation");
                    require(!artifact.contains("uriBaseId") && !artifact.contains("index"), "SARIF indirect artifact locations are unsupported");
                    auto path = text(artifact, "uri");
                    f["asset"] = {{"kind", "file"}, {"id", path}}; f["location"] = {{"path", path}};
                    if (loc.contains("region") && loc["region"].contains("startLine")) f["location"]["line"] = loc["region"]["startLine"];
                    if (loc.contains("region") && loc["region"].contains("startColumn")) f["location"]["column"] = loc["region"]["startColumn"];
                }
                if (r.contains("properties") && r["properties"].contains("rudyAsset")) {
                    f["asset"] = r["properties"]["rudyAsset"];
                    f["location"] = r["properties"].value("rudyLocation", J::object());
                    f["title"] = r["properties"].value("rudyTitle", f["title"]);
                    f["evidence"] = r["properties"].value("rudyEvidence", J::array());
                    f["identifiers"] = r["properties"].value("rudyIdentifiers", J::array());
                    if (r["properties"].contains("rudyScope")) f["scope"] = r["properties"]["rudyScope"];
                }
                require((r.contains("locations") && !r["locations"].empty()) || (r.contains("properties") && r["properties"].contains("rudyAsset")), "SARIF result requires a physical location or rudyAsset");
                require(!r.contains("suppressions") || r["suppressions"].empty(), "SARIF suppressions are unsupported");
                add(std::move(f));
            }
        }
    } else if (format == "rudy-web-audit") {
        require(doc.is_object() && doc.value("schema_version", 0) == 1 && doc.value("tool", "") == "Rudy Web Audit", "Unsupported Rudy Web Audit report");
        require(doc.at("targets").is_array(), "Invalid web target list");
        for (const auto& target : doc.at("targets")) {
          require(target.at("checks").is_array(), "Invalid web check list");
          for (const auto& check : target.at("checks")) {
            auto status = text(check, "status");
            require(status == "pass" || status == "info" || status == "warn" || status == "fail", "Invalid web check status");
            if (status != "warn" && status != "fail") continue;
            auto f = base("rudy-web-audit", text(check, "id"), text(check, "title"), text(check, "severity"), "url", text(target, "target"), J::array({text(check, "evidence", false)}));
            if (check.contains("hop") && !check["hop"].is_null()) {
                require(check["hop"].is_number_unsigned(), "Invalid web hop");
                f["location"] = {{"path", "hop:" + check["hop"].dump()}};
            }
            add(std::move(f));
          }
        }
    } else if (format == "rudy-sentinel") {
        require(doc.is_array(), "Sentinel input must be an alert array");
        for (const auto& r : doc) {
            require(r.is_object(), "Invalid Sentinel record");
            if (r.value("kind", "") != "alert") continue;
            auto f = base("rudy-sentinel", text(r, "rule_id"), text(r, "title"), text(r, "severity"), "process", text(r, "process_id"));
            require(r.at("sequence").is_number_unsigned(), "Invalid Sentinel sequence");
            f["location"] = {{"path", "sequence:" + r.at("sequence").dump()}};
            f["identifiers"] = J::array({text(r, "mitre")});
            f["evidence"] = J::array({text(r, "image"), text(r, "interpretation", false)});
            add(std::move(f));
        }
    } else fail("Unsupported input format");
    // Adapters may synthesize text. Apply the same policy after extraction too.
    redact(found, replacements);
    return bundle(std::move(found), J::array({{{"format", format}, {"scope", scope}, {"digest", digest(raw)}}}), replacements);
}
std::string uri_path(const std::string& path) {
    constexpr char hex[] = "0123456789ABCDEF"; std::string out;
    for (unsigned char c : path) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || std::string_view("-._~/:").find(static_cast<char>(c)) != std::string_view::npos) out += static_cast<char>(c);
        else { out += '%'; out += hex[c >> 4]; out += hex[c & 15]; }
    }
    return out;
}
J sarif(const J& b) {
    std::map<std::string, J> groups;
    for (const auto& f : b["findings"]) {
        auto producer = f["producer"].get<std::string>();
        if (!groups.contains(producer)) groups[producer] = {{"tool", {{"driver", {{"name", producer}}}}}, {"results", J::array()}};
        auto s = f["severity"].get<std::string>(); auto level = rank(s) >= 3 ? "error" : rank(s) >= 1 ? "warning" : "note";
        J result{{"ruleId", f["rule_id"]}, {"level", level}, {"message", {{"text", f["title"]}}},
            {"partialFingerprints", {{"rudy/v1", f["fingerprint"]}}},
            {"properties", {{"rudyScope", f["scope"]}, {"rudySeverity", s}, {"rudyTitle", f["title"]}, {"rudyAsset", f["asset"]},
                {"rudyLocation", f["location"]}, {"rudyEvidence", f["evidence"]}, {"rudyIdentifiers", f["identifiers"]}}}};
        if (f["asset"]["kind"] == "file") {
            auto path = f["location"].value("path", f["asset"]["id"].get<std::string>());
            J loc{{"artifactLocation", {{"uri", uri_path(path)}}}};
            if (f["location"].contains("line")) loc["region"] = {{"startLine", f["location"]["line"]}};
            if (f["location"].contains("line") && f["location"].contains("column")) loc["region"]["startColumn"] = f["location"]["column"];
            result["locations"] = J::array({{{"physicalLocation", loc}}});
        }
        groups[producer]["results"].push_back(std::move(result));
    }
    J runs = J::array(); for (auto& [name, run] : groups) { (void)name; runs.push_back(std::move(run)); }
    return {{"$schema", "https://json.schemastore.org/sarif-2.1.0.json"}, {"version", "2.1.0"}, {"runs", runs}};
}
J execute(const J& request) {
    require(request.is_object(), "Request must be an object");
    auto op = text(request, "operation");
    if (op == "redact") { auto doc = request.at("document"); std::size_t count = 0; redact(doc, count); return {{"document", doc}, {"replacements", count}, {"policy", "builtin-v1"}}; }
    if (op == "digest") return {{"algorithm", "blake3-256"}, {"digest", digest(text(request, "text", false))}};
    if (op == "normalize") {
        const auto& doc = request.at("document"); return normalize(text(request, "format"), text(request, "scope"), doc, doc.dump());
    }
    if (op == "normalize-lines") {
        require(request.at("text").is_string(), "NDJSON text must be a string");
        auto input = request["text"].get<std::string>(); J rows = J::array(); std::size_t offset = 0;
        while (offset < input.size()) {
            auto end = input.find('\n', offset); if (end == std::string::npos) end = input.size();
            auto line = std::string_view(input).substr(offset, end - offset);
            if (std::any_of(line.begin(), line.end(), [](char c) { return !space(c); })) {
                require(rows.size() < max_findings, "NDJSON record count exceeds 10000"); rows.push_back(parse(line));
            }
            offset = end + 1;
        }
        return normalize(text(request, "format"), text(request, "scope"), std::move(rows), input);
    }
    if (op == "validate") { auto b = validate(request.at("document")); return {{"valid", true}, {"findings", b["findings"].size()}, {"digest", b["integrity"]["digest"]}}; }
    if (op == "sarif") return sarif(validate(request.at("document")));
    if (op == "merge") {
        const auto& docs = request.at("documents"); require(docs.is_array() && !docs.empty() && docs.size() <= 128, "Merge requires 1 to 128 bundles");
        J items = J::array(), sources = J::array(); std::size_t replacements = 0;
        std::set<std::string> seen;
        for (const auto& doc : docs) {
            auto b = validate(doc);
            if (!seen.insert(b["integrity"]["digest"].get<std::string>()).second) continue;
            require(items.size() + b["findings"].size() <= max_findings, "Merged finding count exceeds 10000");
            for (auto& f : b["findings"]) items.push_back(std::move(f));
            for (auto& s : b["sources"]) sources.push_back(std::move(s));
            auto count = b["redaction"]["replacements"].get<std::size_t>();
            require(count <= max_input_bytes && replacements <= max_input_bytes - count, "Redaction count exceeds limit"); replacements += count;
        }
        require(sorted_unique(sources).size() <= 128, "Merged source count exceeds 128");
        return bundle(std::move(items), std::move(sources), replacements);
    }
    if (op == "diff") {
        auto before = validate(request.at("baseline")), after = validate(request.at("document"));
        std::map<std::string, J> old, now;
        for (const auto& f : before["findings"]) old.emplace(f["fingerprint"].get<std::string>(), f);
        for (const auto& f : after["findings"]) now.emplace(f["fingerprint"].get<std::string>(), f);
        J result{{"schema", "rudy-evidence-diff/v1"}, {"added", J::array()}, {"absent", J::array()}, {"changed", J::array()}, {"unchanged", J::array()},
            {"baseline_digest", before["integrity"]["digest"]}, {"current_digest", after["integrity"]["digest"]}};
        for (const auto& [id, f] : now) {
            if (!old.contains(id)) result["added"].push_back(f);
            else if (old[id] != f) result["changed"].push_back({{"before", old[id]}, {"after", f}});
            else result["unchanged"].push_back(id);
        }
        for (const auto& [id, f] : old) if (!now.contains(id)) result["absent"].push_back(f);
        return result;
    }
    fail("Unsupported operation");
}
}
std::string process(std::string_view request) {
    try {
        auto result = execute(parse(request)).dump();
        require(result.size() <= max_input_bytes, "Output exceeds 16 MiB"); return result;
    } catch (const J::exception&) { throw Error("Invalid JSON syntax or field type"); }
}
}
