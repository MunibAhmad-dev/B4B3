/*
  Exercise 03 — Corpus Manager
  ------------------------------
  A coverage-guided fuzzer only saves inputs that increase coverage.
  This exercise builds a corpus manager that:
    1. Tracks which "coverage slots" each input triggers.
    2. Accepts or rejects new test cases based on whether they add new coverage.
    3. Minimizes the corpus — removes redundant inputs.

  We simulate coverage as a bitmask (256 bits / 32 bytes, AFL-style).
  Each bit represents one "edge" (branch) in the target program.

  Tasks:
  1. Implement CorpusEntry::covers(other) — returns true if `this` covers
     all bits that `other` covers (subset check).
  2. Implement CorpusManager::addIfNew(input, coverage) — add the input
     to the corpus only if `coverage` includes at least one new bit.
     Update g_globalCoverage.
  3. Implement CorpusManager::minimize() — remove inputs from the corpus
     that are fully covered by other inputs combined (greedy set cover).
  4. Implement a simulation loop: generate 1000 random "inputs" with random
     "coverages", run them through the manager, print final corpus size.

  BONUS:
  - Implement energy scheduling: inputs with rare coverage get fuzzed more
    (higher energy). Measure "rarity" as 1/popcount(coverage) normalized.
  - Implement havoc mutations (byte flip, bit flip, splice, known-int insertion)
    directly in this file to generate test cases without WinAFL.

  Compile:
    g++ -std=c++17 -Wall -o ex03.exe ex03_corpus_manager.cpp
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

static const int BITMAP_BYTES = 32;  // 256-bit coverage bitmap (AFL uses 64 KB)

typedef std::array<BYTE, BITMAP_BYTES> Bitmap;

struct CorpusEntry {
    std::string  name;
    std::string  data;
    Bitmap       coverage;

    // TODO 1: return true if this entry's coverage is a subset of other's
    bool subsetOf(const Bitmap& other) const {
        // for each byte: (coverage[i] & ~other[i]) == 0 means all bits in ours are in other
        for (int i = 0; i < BITMAP_BYTES; i++)
            if (coverage[i] & ~other[i]) return false;
        return true;
    }

    // Return true if this entry covers at least one bit NOT in globalCoverage
    bool isNew(const Bitmap& globalCoverage) const {
        for (int i = 0; i < BITMAP_BYTES; i++)
            if (coverage[i] & ~globalCoverage[i]) return true;
        return false;
    }
};

class CorpusManager {
public:
    std::vector<CorpusEntry> entries;
    Bitmap globalCoverage = {};

    // TODO 2: add input if it covers at least one new bit
    bool addIfNew(const std::string& name, const std::string& data, const Bitmap& cov) {
        CorpusEntry e{ name, data, cov };
        if (!e.isNew(globalCoverage)) return false;

        // YOUR CODE HERE:
        // Update globalCoverage with new bits from cov
        // entries.push_back(e)
        // return true;
        (void)e;
        return false; // replace
    }

    // TODO 3: remove entries fully covered by the union of remaining entries
    void minimize() {
        // Greedy set cover:
        // Keep re-scanning until no removals are made in a pass
        bool changed = true;
        while (changed) {
            changed = false;
            for (size_t i = 0; i < entries.size(); i++) {
                // Build union of coverage for all entries except i
                Bitmap unionWithout = {};
                for (size_t j = 0; j < entries.size(); j++) {
                    if (j == i) continue;
                    for (int k = 0; k < BITMAP_BYTES; k++)
                        unionWithout[k] |= entries[j].coverage[k];
                }
                // YOUR CODE HERE:
                // if entries[i].subsetOf(unionWithout):
                //   entries.erase(entries.begin() + i)
                //   changed = true; break;
                (void)unionWithout;
            }
        }
    }

    int bitCount(const Bitmap& b) const {
        int n = 0;
        for (auto byte : b)
            for (int i = 0; i < 8; i++) n += (byte >> i) & 1;
        return n;
    }

    void printStats() const {
        printf("[CORPUS] Entries: %zu  GlobalCoverage: %d / %d bits\n",
               entries.size(), 0, BITMAP_BYTES * 8);
        // replace 0 with bitCount(globalCoverage)
    }
};

// ---------- Simulation ----------
Bitmap randomCoverage(int numBitsSet) {
    Bitmap b = {};
    for (int i = 0; i < numBitsSet; i++) {
        int bit = rand() % (BITMAP_BYTES * 8);
        b[bit / 8] |= (1 << (bit % 8));
    }
    return b;
}

int main() {
    srand((unsigned)time(nullptr));
    CorpusManager mgr;

    // Seed corpus: 5 entries with known good coverage
    for (int i = 0; i < 5; i++) {
        Bitmap cov = randomCoverage(10 + i * 5);
        mgr.addIfNew("seed_" + std::to_string(i), "seed data", cov);
    }
    printf("[*] After seeds:\n"); mgr.printStats();

    // Fuzz loop: 1000 random test cases
    int accepted = 0;
    for (int i = 0; i < 1000; i++) {
        Bitmap cov = randomCoverage(rand() % 20 + 1);
        if (mgr.addIfNew("input_" + std::to_string(i), "fuzz data", cov))
            accepted++;
    }
    printf("[*] After 1000 inputs (%d accepted):\n", accepted);
    mgr.printStats();

    // Minimize
    mgr.minimize();
    printf("[*] After minimize:\n");
    mgr.printStats();

    return 0;
}
