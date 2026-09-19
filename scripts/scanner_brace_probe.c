/* Regression for dcg #442. Compile against the actual tree-sitter-bash scanner:
 * cc -std=c11 -O1 -g -I vendor/tree-sitter-bash/src \
 *    scripts/scanner_brace_probe.c -o /tmp/scanner-brace-probe
 * /tmp/scanner-brace-probe
 *
 * -DCHECK_CTYPE_DOMAIN makes an unpatched scanner fail deterministically with
 * exit 86, even when its out-of-bounds libc table read happens to be mapped.
 * Instrument only this binary with ASAN/UBSAN; do not set global Cargo CFLAGS.
 */
#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef CHECK_CTYPE_DOMAIN
static int checked_isdigit(int32_t c) {
    if (c != EOF && (c < 0 || c > UCHAR_MAX)) {
        fprintf(stderr, "ctype-domain violation: isdigit(U+%06X)\n", (unsigned)c);
        exit(86);
    }
    return c >= '0' && c <= '9';
}
#undef isdigit
#define isdigit(c) checked_isdigit(c)
#endif

#include "scanner.c"

typedef struct {
    TSLexer lexer; /* First field: callback casts preserve the object's address. */
    const int32_t *input;
    size_t length;
    size_t position;
    size_t marked_end;
} ProbeLexer;

static void probe_advance(TSLexer *lexer, bool skip) {
    (void)skip;
    ProbeLexer *probe = (ProbeLexer *)lexer;
    if (probe->position < probe->length) {
        probe->position++;
    }
    lexer->lookahead = probe->position < probe->length ? probe->input[probe->position] : 0;
}

static void probe_mark_end(TSLexer *lexer) {
    ProbeLexer *probe = (ProbeLexer *)lexer;
    probe->marked_end = probe->position;
}

static uint32_t probe_column(TSLexer *lexer) {
    return (uint32_t)((ProbeLexer *)lexer)->position;
}

static bool probe_eof(const TSLexer *lexer) {
    const ProbeLexer *probe = (const ProbeLexer *)lexer;
    return probe->position >= probe->length;
}

static bool probe_range_start(const TSLexer *lexer) {
    (void)lexer;
    return false;
}

static void check(void *scanner, const int32_t *input, size_t length, bool expected) {
    ProbeLexer probe = {
        .lexer = {
            .lookahead = length ? input[0] : 0,
            .advance = probe_advance,
            .mark_end = probe_mark_end,
            .get_column = probe_column,
            .is_at_included_range_start = probe_range_start,
            .eof = probe_eof,
        },
        .input = input,
        .length = length,
    };
    bool symbols[ERROR_RECOVERY + 1] = {false};
    symbols[BRACE_START] = true;
    bool actual = tree_sitter_bash_external_scanner_scan(scanner, &probe.lexer, symbols);
    if (actual != expected || (actual && (probe.lexer.result_symbol != BRACE_START || probe.marked_end != 1))) {
        fprintf(stderr, "brace scanner mismatch: expected=%d actual=%d position=%zu\n",
                expected, actual, probe.position);
        exit(1);
    }
}

int main(void) {
    void *scanner = tree_sitter_bash_external_scanner_create();
    if (!scanner) {
        fputs("scanner allocation failed\n", stderr);
        return 1;
    }
    /* Check the high scalar first so the unfixed scanner's failure is concise. */
    const int32_t trigger[] = {'{', 0x10ffff, '.', '.', '1', '}'};
    check(scanner, trigger, sizeof(trigger) / sizeof(trigger[0]), false);
    const int32_t valid[] = {'{', '1', '2', '.', '.', '3', '4', '}'};
    check(scanner, valid, sizeof(valid) / sizeof(valid[0]), true);
    const int32_t truncated[] = {'{', '1', '.', '.'};
    check(scanner, truncated, sizeof(truncated) / sizeof(truncated[0]), false);

    /* Exhaust both loops, including the continuation after an ASCII digit.
     * Low-byte aliases such as U+0130 must not become ASCII '0' via a cast.
     */
    unsigned long cases = 3;
    for (int32_t cp = 0; cp <= 0x10ffff; cp++) {
        if (cp >= 0xd800 && cp <= 0xdfff) {
            continue; /* Surrogates are not Unicode scalar values. */
        }
        const int32_t first[] = {'{', cp, '.', '.', '9', '}'};
        const int32_t first_tail[] = {'{', '1', cp, '.', '.', '9', '}'};
        const int32_t second[] = {'{', '1', '.', '.', cp, '}'};
        const int32_t second_tail[] = {'{', '1', '.', '.', '2', cp, '}'};
        const bool digit = cp >= '0' && cp <= '9';
        check(scanner, first, sizeof(first) / sizeof(first[0]), digit);
        check(scanner, first_tail, sizeof(first_tail) / sizeof(first_tail[0]), digit);
        /* The original scanner also accepts an empty upper endpoint; preserve
         * that behavior when cp is '}', rather than changing grammar here. */
        check(scanner, second, sizeof(second) / sizeof(second[0]), digit || cp == '}');
        check(scanner, second_tail, sizeof(second_tail) / sizeof(second_tail[0]), digit || cp == '}');
        cases += 4;
    }
    tree_sitter_bash_external_scanner_destroy(scanner);
    printf("PASS: %lu actual-scanner cases (all Unicode scalars, both digit loops)\n", cases);
    return 0;
}
