// Safe regex: mutually exclusive alternation branches — NOT a ReDoS risk
// The branches start with '"' vs [^\s"] (char class that excludes '"').
// The engine can always disambiguate on the first character; no exponential backtracking.

const TOKEN_RE = /(?:"[^"]*"|[^\s"])+/g;

export function tokenize(input: string): string[] {
    return input.match(TOKEN_RE) ?? [];
}

// Safe: single-quoted variant, same mutual-exclusion property
const SQTOKEN_RE = /(?:'[^']*'|[^\s'])+/g;

export function tokenizeSQ(input: string): string[] {
    return input.match(SQTOKEN_RE) ?? [];
}
