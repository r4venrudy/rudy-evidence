#include "rudy/evidence.hpp"
#include <nlohmann/json.hpp>
#include <array>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shellapi.h>
#include <fcntl.h>
#include <io.h>
#endif
namespace {
using J = nlohmann::json;
std::string read(const std::string& path) {
    std::ifstream file;
    if (path != "-") { file.open(std::filesystem::path(std::u8string(path.begin(), path.end())), std::ios::binary); if (!file) throw rudy::evidence::Error("Cannot open input file"); }
    std::istream& in = path == "-" ? std::cin : file;
    std::string result; std::array<char, 8192> bytes{};
    while (in) {
        in.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        auto count = static_cast<std::size_t>(in.gcount());
        if (count > rudy::evidence::max_input_bytes - result.size()) throw rudy::evidence::Error("Input exceeds 16 MiB");
        result.append(bytes.data(), count);
    }
    if (in.bad()) throw rudy::evidence::Error("Cannot read input file");
    return result;
}
void help() {
    std::cout << "Rudy Evidence " << rudy::evidence::version << "\n"
      "Offline security evidence SDK. UTF-8 JSON to stdout; errors to stderr.\n"
      "  request [JSON|-]\n  normalize FORMAT SCOPE [JSON|-]\n"
      "  normalize-lines FORMAT SCOPE [NDJSON|-]\n  validate [BUNDLE|-]\n"
      "  sarif [BUNDLE|-]\n  redact [JSON|-]\n  diff BASELINE CURRENT\n"
      "  merge BUNDLE...\n  --version\n"
      "Formats: native, semgrep, nuclei, trivy, sarif, rudy-web-audit, rudy-sentinel.\n";
}
}
int main(int argc, char** argv) {
#ifdef _WIN32
    _setmode(_fileno(stdin), _O_BINARY); _setmode(_fileno(stdout), _O_BINARY);
#endif
    try {
        std::vector<std::string> a(argv + 1, argv + argc);
#ifdef _WIN32
        int count = 0; auto wide = CommandLineToArgvW(GetCommandLineW(), &count);
        if (!wide) throw rudy::evidence::Error("Cannot read command line");
        a.clear();
        for (int i = 1; i < count; ++i) {
            int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide[i], -1, nullptr, 0, nullptr, nullptr);
            if (!bytes) { LocalFree(wide); throw rudy::evidence::Error("Invalid command line encoding"); }
            std::string value(static_cast<std::size_t>(bytes), '\0');
            WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide[i], -1, value.data(), bytes, nullptr, nullptr);
            value.pop_back(); a.push_back(std::move(value));
        }
        LocalFree(wide);
#endif
        if (a.empty() || a[0] == "--help") { help(); return 0; }
        if (a[0] == "--version" && a.size() == 1) { std::cout << rudy::evidence::version << '\n'; return 0; }
        std::string req;
        if (a[0] == "request" && a.size() <= 2) req = read(a.size() == 2 ? a[1] : "-");
        else if ((a[0] == "normalize" || a[0] == "normalize-lines") && (a.size() == 3 || a.size() == 4)) {
            auto raw = read(a.size() == 4 ? a[3] : "-");
            req = "{\"operation\":" + J(a[0]).dump() + ",\"format\":" + J(a[1]).dump() + ",\"scope\":" + J(a[2]).dump();
            req += a[0] == "normalize" ? ",\"document\":" + raw : ",\"text\":" + J(raw).dump(); req += '}';
        } else if ((a[0] == "validate" || a[0] == "sarif" || a[0] == "redact") && a.size() <= 2)
            req = "{\"operation\":" + J(a[0]).dump() + ",\"document\":" + read(a.size() == 2 ? a[1] : "-") + '}';
        else if (a[0] == "diff" && a.size() == 3)
            req = "{\"operation\":\"diff\",\"baseline\":" + read(a[1]) + ",\"document\":" + read(a[2]) + '}';
        else if (a[0] == "merge" && a.size() >= 2 && a.size() <= 129) {
            req = "{\"operation\":\"merge\",\"documents\":[";
            for (std::size_t i = 1; i < a.size(); ++i) {
                if (i != 1) req += ','; req += read(a[i]);
                if (req.size() > rudy::evidence::max_input_bytes) throw rudy::evidence::Error("Combined input exceeds 16 MiB");
            }
            req += "]}";
        } else { std::cerr << "Invalid arguments. Use --help.\n"; return 2; }
        std::cout << rudy::evidence::process(req) << '\n';
        if (!std::cout) return 3;
        return 0;
    } catch (const rudy::evidence::Error& e) { std::cerr << "Rudy Evidence: " << e.what() << '\n'; return 1; }
    catch (...) { std::cerr << "Rudy Evidence: internal or encoding error\n"; return 3; }
}
