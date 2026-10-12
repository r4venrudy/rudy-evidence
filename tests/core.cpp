#include "rudy/evidence.hpp"
#include <atomic>
#include <iostream>
#include <thread>
#include <vector>
int main() {
    const auto request = R"({"operation":"digest","text":"abc"})";
    const auto expected = R"({"algorithm":"blake3-256","digest":"blake3:6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"})";
    std::atomic<int> failures{0}; std::vector<std::thread> workers;
    for (int t = 0; t < 8; ++t) workers.emplace_back([&] {
        for (int n = 0; n < 1000; ++n) {
            try { if (rudy::evidence::process(request) != expected) ++failures; }
            catch (...) { ++failures; }
        }
    });
    for (auto& worker : workers) worker.join();
    try { rudy::evidence::process("{\"operation\":\"digest\",\"operation\":\"redact\"}"); ++failures; }
    catch (const rudy::evidence::Error&) {}
    if (failures) { std::cerr << failures << " failures\n"; return 1; }
    std::cout << "8,000 concurrent API calls and duplicate-key rejection passed\n";
}
