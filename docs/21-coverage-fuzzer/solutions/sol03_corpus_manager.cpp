/*
  Solution 03 — Corpus Manager (Complete)
  ----------------------------------------
  A coverage-guided fuzzer only saves inputs that increase coverage.
  This implementation tracks 256-bit edge bitmaps (AFL-style),
  accepts new inputs that cover new bits, and minimizes the corpus
  with a greedy set-cover algorithm.

  Compile:
    g++ -std=c++17 -Wall -o sol03.exe sol03_corpus_manager.cpp
*/

#include <windows.h>
#include <vector>
#include <string>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <algorithm>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

static const int BITMAP_BYTES = 32;  // 256-bit coverage bitmap

typedef std::array<BYTE, BITMAP_BYTES> Bitmap;


// =========================================================
// Bitmap helpers
// =========================================================

// Count total set bits in a bitmap
static int bitCount(const Bitmap& b) {
    int n = 0;
    for (auto byte : b)
        for (int i = 0; i < 8; i++) n += (byte >> i) & 1;
    return n;
}

// Returns true if every bit set in 'needle' is also set in 'haystack'
static bool isSubset(const Bitmap& needle, const Bitmap& haystack) {
    for (int i = 0; i < BITMAP_BYTES; i++)
        if (needle[i] & ~haystack[i]) return false;
    return true;
}

// Returns true if 'cov' has at least one bit NOT in 'global'
static bool hasNewBits(const Bitmap& cov, const Bitmap& global) {
    for (int i = 0; i < BITMAP_BYTES; i++)
        if (cov[i] & ~global[i]) return true;
    return false;
}

// Merge src bits into dst
static void mergeBitmap(Bitmap& dst, const Bitmap& src) {
    for (int i = 0; i < BITMAP_BYTES; i++)
        dst[i] |= src[i];
}


// =========================================================
// CorpusEntry
// =========================================================
struct CorpusEntry {
    std::string name;       // input identifier / filename
    std::string data;       // raw bytes of the input
    Bitmap      coverage;   // edge bitmap produced by this input

    // True if every bit in our coverage is already in 'other'
    bool subsetOf(const Bitmap& other) const {
        return isSubset(coverage, other);
    }

    // True if we cover at least one bit not yet in globalCoverage
    bool isNew(const Bitmap& globalCoverage) const {
        return hasNewBits(coverage, globalCoverage);
    }
};


// =========================================================
// CorpusManager
// =========================================================
class CorpusManager {
public:
    std::vector<CorpusEntry> entries;
    Bitmap globalCoverage = {};

    // ---------------------------------------------------------
    // addIfNew: accept input only if it covers at least one new edge
    // ---------------------------------------------------------
    bool addIfNew(const std::string& name,
                  const std::string& data,
                  const Bitmap& cov) {
        CorpusEntry e{ name, data, cov };
        if (!e.isNew(globalCoverage)) return false;

        // Merge new bits into the global coverage bitmap
        mergeBitmap(globalCoverage, cov);

        entries.push_back(std::move(e));
        return true;
    }

    // ---------------------------------------------------------
    // minimize: greedy set-cover removal
    //
    // Algorithm:
    //   Repeat until stable:
    //     For each entry i:
    //       Build union of all OTHER entries' coverage.
    //       If entry i's coverage is a subset of that union,
    //       entry i is redundant — remove it.
    // ---------------------------------------------------------
    void minimize() {
        bool changed = true;
        while (changed) {
            changed = false;
            for (size_t i = 0; i < entries.size(); i++) {
                // Build the union of coverage for all entries except i
                Bitmap unionWithout = {};
                for (size_t j = 0; j < entries.size(); j++) {
                    if (j == i) continue;
                    mergeBitmap(unionWithout, entries[j].coverage);
                }
                // If removing entry[i] does not reduce global coverage, drop it
                if (entries[i].subsetOf(unionWithout)) {
                    printf("[MIN]  Removing redundant entry: %s\n",
                           entries[i].name.c_str());
                    entries.erase(entries.begin() + (ptrdiff_t)i);
                    changed = true;
                    break;   // restart the loop after removal
                }
            }
        }
    }

    // ---------------------------------------------------------
    // Optional: save corpus entries to a directory on disk
    // ---------------------------------------------------------
    void saveToDisk(const std::string& dir) const {
        fs::create_directories(dir);
        for (auto& e : entries) {
            std::string path = dir + "/" + e.name;
            std::ofstream f(path, std::ios::binary);
            if (f) f.write(e.data.data(), (std::streamsize)e.data.size());
        }
        printf("[CORPUS] Saved %zu entries to '%s'\n", entries.size(), dir.c_str());
    }

    // ---------------------------------------------------------
    // Energy scheduling: inputs with rarer (lower-popcount)
    // coverage deserve more fuzzing iterations.
    // Returns a weight in [1, 100].
    // ---------------------------------------------------------
    int energyFor(const CorpusEntry& e) const {
        int pop = bitCount(e.coverage);
        if (pop == 0) return 1;
        // Rarer coverage = higher energy
        int maxPop = BITMAP_BYTES * 8;
        return std::max(1, (maxPop - pop) * 100 / maxPop);
    }

    // ---------------------------------------------------------
    // printStats
    // ---------------------------------------------------------
    void printStats() const {
        int covered = bitCount(globalCoverage);
        printf("[CORPUS] Entries: %zu  GlobalCoverage: %d / %d bits  (%.1f%%)\n",
               entries.size(),
               covered,
               BITMAP_BYTES * 8,
               100.0 * covered / (BITMAP_BYTES * 8));
    }
};


// =========================================================
// Simulation helpers
// =========================================================
static Bitmap randomCoverage(int numBitsSet) {
    Bitmap b = {};
    for (int i = 0; i < numBitsSet; i++) {
        int bit = rand() % (BITMAP_BYTES * 8);
        b[bit / 8] |= (BYTE)(1 << (bit % 8));
    }
    return b;
}


// =========================================================
// main — simulation
// =========================================================
int main() {
    srand((unsigned)time(nullptr));
    CorpusManager mgr;

    printf("=== Corpus Manager Simulation ===\n\n");

    // ---- Phase 1: seed corpus ----
    printf("[*] Seeding with 5 entries...\n");
    for (int i = 0; i < 5; i++) {
        Bitmap cov = randomCoverage(10 + i * 5);
        bool   ok  = mgr.addIfNew("seed_" + std::to_string(i),
                                  "seed data " + std::to_string(i), cov);
        printf("  seed_%d: %s  (bits set: %d)\n",
               i, ok ? "ACCEPTED" : "rejected", bitCount(cov));
    }
    printf("\n[*] After seeds:\n");
    mgr.printStats();

    // ---- Phase 2: 1000 random fuzzer inputs ----
    printf("\n[*] Fuzzing loop (1000 inputs)...\n");
    int accepted = 0;
    for (int i = 0; i < 1000; i++) {
        int    nbits = rand() % 20 + 1;
        Bitmap cov   = randomCoverage(nbits);
        if (mgr.addIfNew("input_" + std::to_string(i),
                         "fuzz data", cov))
            accepted++;
    }
    printf("[*] Accepted %d / 1000 inputs (those that added new coverage)\n",
           accepted);
    printf("\n[*] After fuzzing:\n");
    mgr.printStats();

    // ---- Phase 3: energy scheduling demo ----
    printf("\n[*] Top-5 highest-energy inputs (rarest coverage):\n");
    {
        std::vector<std::pair<int,std::string>> ranked;
        for (auto& e : mgr.entries)
            ranked.push_back({ mgr.energyFor(e), e.name });
        std::sort(ranked.rbegin(), ranked.rend());
        int shown = 0;
        for (auto& [energy, name] : ranked) {
            printf("  energy=%-3d  %s\n", energy, name.c_str());
            if (++shown >= 5) break;
        }
    }

    // ---- Phase 4: minimize ----
    printf("\n[*] Minimizing corpus...\n");
    size_t before = mgr.entries.size();
    mgr.minimize();
    printf("[*] Reduced from %zu to %zu entries\n",
           before, mgr.entries.size());
    printf("\n[*] After minimize:\n");
    mgr.printStats();

    // ---- Verify: global coverage unchanged after minimize ----
    printf("\n[*] Verifying coverage preserved...\n");
    Bitmap recomputed = {};
    for (auto& e : mgr.entries)
        mergeBitmap(recomputed, e.coverage);
    bool ok = (recomputed == mgr.globalCoverage);
    printf("[%s] Coverage after minimize %s original global bitmap\n",
           ok ? "PASS" : "FAIL",
           ok ? "matches" : "does NOT match");

    return ok ? 0 : 1;
}
