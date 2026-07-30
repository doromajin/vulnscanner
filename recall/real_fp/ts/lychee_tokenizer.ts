// Extracted from Lychee/resources/js/composables/useSearchTokenAssembler.ts
// Safe tokenizer regex — was incorrectly flagged as JSAST-REDOS-001.
// The two alternation branches start with mutually exclusive first characters:
//   branch 1: "..." (starts with literal ")
//   branch 2: [^\s"] (char class that EXCLUDES ")
// Modern engines like V8 can always disambiguate on the first character;
// there is no ambiguous path that leads to exponential backtracking.

export function parseTokens(input: string): string[] {
    const TOKEN_RE = /(?:"[^"]*"|[^\s"])+/g;
    return input.match(TOKEN_RE) ?? [];
}
