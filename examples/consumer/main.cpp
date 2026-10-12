#include <rudy/evidence.hpp>
#include <iostream>
int main() {
    try { std::cout << rudy::evidence::process(R"({"operation":"digest","text":"abc"})") << '\n'; }
    catch (...) { return 1; }
}
