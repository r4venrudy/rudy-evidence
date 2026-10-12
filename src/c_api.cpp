#define RE_BUILD_DLL
#include "rudy/evidence.h"
#include "rudy/evidence.hpp"
#include <cstdlib>
#include <cstring>
#include <new>

namespace {
bool assign(re_buffer *out, std::string_view text) noexcept {
    auto *memory = static_cast<char *>(std::malloc(text.size() + 1));
    if (!memory) return false;
    std::memcpy(memory, text.data(), text.size());
    memory[text.size()] = '\0'; out->data = memory; out->size = text.size();
    return true;
}
}
unsigned int re_abi_version(void) { return 1; }
const char *re_version(void) { return "0.1.0"; }
void re_free(re_buffer *buffer) {
    if (!buffer) return;
    std::free(buffer->data); buffer->data = nullptr; buffer->size = 0;
}
int re_process(const char *request, size_t length, re_buffer *result, re_buffer *error) {
    if (!result || !error || result == error || result->data || result->size || error->data || error->size || (!request && length))
        return RE_INVALID_ARGUMENT;
    try {
        auto output = rudy::evidence::process(std::string_view(request ? request : "", length));
        if (!assign(result, output)) return RE_INTERNAL_ERROR;
        return RE_OK;
    } catch (const rudy::evidence::Error& e) {
        assign(error, e.what()); return RE_INVALID_INPUT;
    } catch (...) {
        assign(error, "Internal processing failure"); return RE_INTERNAL_ERROR;
    }
}
