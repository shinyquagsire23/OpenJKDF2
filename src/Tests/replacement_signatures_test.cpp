// Synthetic entries exercise the actual production registration and selection blocks.
#include <cassert>
#include <cstdio>
#include <string>
#include <unordered_map>
#if __has_include("Platform/GL/jkgm_cache_lookup.hpp")
#include "Platform/GL/jkgm_cache_lookup.hpp"
#endif
struct CacheEntry { int marker; };
using Cache = std::unordered_map<std::string, CacheEntry>;
struct Signature {
    std::string value;
    operator std::string() const { return value; }
    template<typename T> T get() const { return value; }
};
static void register_entry(Cache& jkgm_cache_hash, const std::string& key, const CacheEntry& entry) {
    Signature hash_it{key};
#include "actual_register.inc"
}
struct Texture { CacheEntry* cache_entry; int skip_jkgm; };
static CacheEntry* find_entry(Cache& jkgm_cache, const std::string& cache_key,
                             Cache& jkgm_cache_hash, const std::string& hash) {
    Texture result{nullptr, 0};
    Texture* texture = &result;
#include "actual_select.inc"
    assert(texture->skip_jkgm == (texture->cache_entry == nullptr));
    return texture->cache_entry;
}
void test_jkgm_cache_lookup()
{
    using Cache = std::unordered_map<std::string, CacheEntry>;

    Cache first_wins;
    register_entry(first_wins, "duplicate-signature", CacheEntry{1});
    register_entry(first_wins, "duplicate-signature", CacheEntry{2});
    assert(first_wins.size() == 1);
    assert(first_wins.find("duplicate-signature")->second.marker == 1);

    Cache paths{{"mat/example.mat0", {1}}};
    Cache signatures{{"0123456789abcdef", {2}}};

    CacheEntry* path_entry = find_entry(
        paths, std::string("mat/example.mat0"),
        signatures, std::string("missing-signature"));
    assert(path_entry == &paths.find("mat/example.mat0")->second);
    assert(path_entry->marker == 1);

    CacheEntry* signature_entry = find_entry(
        paths, std::string("mat/missing.mat0"),
        signatures, std::string("0123456789abcdef"));
    assert(signature_entry == &signatures.find("0123456789abcdef")->second);
    assert(signature_entry->marker == 2);

    // JkGfxMod's signature identity deliberately wins over a shared path.
    CacheEntry* preferred_entry = find_entry(
        paths, std::string("mat/example.mat0"),
        signatures, std::string("0123456789abcdef"));
    assert(preferred_entry == signature_entry);

    const std::size_t path_size = paths.size();
    const std::size_t signature_size = signatures.size();
    for (int i = 0; i < 3; ++i) {
        CacheEntry* missing_entry = find_entry(
            paths, std::string("mat/missing.mat0"),
            signatures, std::string("missing-signature"));
        assert(missing_entry == nullptr);
    }
    assert(paths.size() == path_size);
    assert(signatures.size() == signature_size);
}

int main() { test_jkgm_cache_lookup(); puts("PASS production replacement registration and selection: duplicate, fallback, signature-only, conflict, non-mutating miss"); }
