#include "rudy/evidence.hpp"
#include <cstddef>
#include <cstdint>
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* bytes, std::size_t size) {
    try { (void)rudy::evidence::process(std::string_view(reinterpret_cast<const char*>(bytes), size)); }
    catch (const rudy::evidence::Error&) {}
    return 0;
}
