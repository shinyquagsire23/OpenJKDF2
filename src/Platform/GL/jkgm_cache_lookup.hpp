#ifndef OPENJKDF2_JKGM_CACHE_LOOKUP_HPP
#define OPENJKDF2_JKGM_CACHE_LOOKUP_HPP

// JkGfxMod keeps the first material that claims a texture signature.  Centralize
// that policy so metadata loading and the asset-free regression test cannot
// silently drift to last-wins assignment.
template <typename CacheMap>
inline bool jkgm_register_signature(
    CacheMap& signature_cache,
    const typename CacheMap::key_type& signature_key,
    const typename CacheMap::mapped_type& entry)
{
    return signature_cache.emplace(signature_key, entry).second;
}

// JkGfxMod identifies replacement materials by the original texture signature.
// Keep OpenJKDF2's path/cel metadata as a fallback for packs that omit a
// signature.  find() is intentional: lookup must not insert a blank entry into
// either cache.
template <typename CacheMap>
inline typename CacheMap::mapped_type* jkgm_find_cache_entry(
    CacheMap& path_cache,
    const typename CacheMap::key_type& path_key,
    CacheMap& signature_cache,
    const typename CacheMap::key_type& signature_key)
{
    auto signature_it = signature_cache.find(signature_key);
    if (signature_it != signature_cache.end()) {
        return &signature_it->second;
    }

    auto path_it = path_cache.find(path_key);
    if (path_it != path_cache.end()) {
        return &path_it->second;
    }

    return nullptr;
}

#endif // OPENJKDF2_JKGM_CACHE_LOOKUP_HPP
