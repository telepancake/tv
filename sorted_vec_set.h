#pragma once

#include <algorithm>
#include <cassert>
#include <utility>
#include <vector>

/*
 * sorted_vec_set<T, Cmp> — a set backed by a lazily-sorted std::vector.
 *
 * Insertions are O(1) amortised (appended, marked unsorted).
 * The first query that needs order triggers an O(n log n) sort + dedup.
 * After that, lookups are O(log n) binary search.
 *
 * This is a good fit when many inserts happen in a batch followed by
 * lookups, or when the data naturally arrives in order (common case).
 */
template<typename T, typename Cmp = std::less<T>>
class sorted_vec_set {
    std::vector<T> v_;
    bool sorted_ = true;
    Cmp cmp_;

    bool equiv(const T &a, const T &b) const { return !cmp_(a,b) && !cmp_(b,a); }

    void ensure_sorted() {
        if (sorted_) return;
        std::sort(v_.begin(), v_.end(), cmp_);
        v_.erase(std::unique(v_.begin(), v_.end(),
                     [this](const T &a, const T &b){ return equiv(a,b); }),
                 v_.end());
        sorted_ = true;
    }
public:
    sorted_vec_set() = default;

    void insert(const T &val) {
        if (!v_.empty() && !cmp_(v_.back(), val)) {
            if (equiv(val, v_.back())) return;
            sorted_ = false;
        }
        v_.push_back(val);
    }
    void insert(T &&val) {
        if (!v_.empty() && !cmp_(v_.back(), val)) {
            if (equiv(val, v_.back())) return;
            sorted_ = false;
        }
        v_.push_back(std::move(val));
    }

    bool contains(const T &val) {
        ensure_sorted();
        return std::binary_search(v_.begin(), v_.end(), val, cmp_);
    }

    /* Heterogeneous lookup — requires Cmp to support comparing T with K.
       Useful with transparent comparators (e.g. looking up by a key
       extracted from the element type). */
    template<typename K>
    bool contains(const K &key) {
        ensure_sorted();
        auto it = std::lower_bound(v_.begin(), v_.end(), key, cmp_);
        return it != v_.end() && !cmp_(key, *it);
    }

    template<typename K>
    bool contains(const K &key) const {
        assert(sorted_);
        auto it = std::lower_bound(v_.begin(), v_.end(), key, cmp_);
        return it != v_.end() && !cmp_(key, *it);
    }

    template<typename K = T>
    typename std::vector<T>::iterator find(const K &key) {
        ensure_sorted();
        auto it = std::lower_bound(v_.begin(), v_.end(), key, cmp_);
        if (it != v_.end() && !cmp_(key, *it)) return it;
        return v_.end();
    }

    template<typename K = T>
    typename std::vector<T>::const_iterator find(const K &key) const {
        assert(sorted_);
        auto it = std::lower_bound(v_.begin(), v_.end(), key, cmp_);
        if (it != v_.end() && !cmp_(key, *it)) return it;
        return v_.end();
    }

    void erase(const T &val) {
        ensure_sorted();
        auto it = std::lower_bound(v_.begin(), v_.end(), val, cmp_);
        if (it != v_.end() && !cmp_(val, *it)) v_.erase(it);
    }

    void clear() { v_.clear(); sorted_ = true; }
    bool empty() const { return v_.empty(); }
    std::size_t size() { ensure_sorted(); return v_.size(); }

    auto begin() { ensure_sorted(); return v_.begin(); }
    auto end()   { ensure_sorted(); return v_.end(); }
    auto begin() const { assert(sorted_); return v_.begin(); }
    auto end()   const { assert(sorted_); return v_.end(); }

    std::pair<typename std::vector<T>::iterator, bool> emplace(const T &val) {
        ensure_sorted();
        auto it = std::lower_bound(v_.begin(), v_.end(), val, cmp_);
        if (it != v_.end() && !cmp_(val, *it)) return {it, false};
        return {v_.insert(it, val), true};
    }

    sorted_vec_set set_union(sorted_vec_set &other) {
        ensure_sorted(); other.ensure_sorted();
        sorted_vec_set out;
        out.v_.reserve(v_.size() + other.v_.size());
        std::set_union(v_.begin(), v_.end(), other.v_.begin(), other.v_.end(),
                       std::back_inserter(out.v_), cmp_);
        out.sorted_ = true;
        return out;
    }
    sorted_vec_set set_intersection(sorted_vec_set &other) {
        ensure_sorted(); other.ensure_sorted();
        sorted_vec_set out;
        std::set_intersection(v_.begin(), v_.end(), other.v_.begin(), other.v_.end(),
                              std::back_inserter(out.v_), cmp_);
        out.sorted_ = true;
        return out;
    }
    sorted_vec_set set_difference(sorted_vec_set &other) {
        ensure_sorted(); other.ensure_sorted();
        sorted_vec_set out;
        std::set_difference(v_.begin(), v_.end(), other.v_.begin(), other.v_.end(),
                            std::back_inserter(out.v_), cmp_);
        out.sorted_ = true;
        return out;
    }
};
