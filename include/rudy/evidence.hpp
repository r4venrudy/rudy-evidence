#pragma once
#include <stdexcept>
#include <string>
#include <string_view>

namespace rudy::evidence {
inline constexpr std::string_view version = "0.1.0";
inline constexpr std::size_t max_input_bytes = 16 * 1024 * 1024;
class Error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};
// UTF-8 JSON request -> UTF-8 JSON response. Throws Error; performs no I/O.
std::string process(std::string_view request);
}
