/**
 * Negative: innerHTML assignments that cannot introduce XSS.
 *
 * XSS-001 checks innerHTM patterns.  Function-call RHS triggers the
 * function-call guard (_innerhtml_is_unsafe returns false).  Ternary with
 * only literal branches triggers the ternary guard ('?' in rhs → false).
 * Template literals where every ${...} is a function call are also safe.
 */

// ── Type-coercion function calls (function-call guard fires) ──────────────────

// String() converts a value to string but cannot inject markup
el.innerHTML = String(count);

// Number methods return numeric strings — no HTML injection possible
el.innerHTML = Number(value).toString();
el.innerHTML = (score * 100).toFixed(2) + "%";

// DOM-sanitizing library calls (already in _SAFE_FUNCS) — verified safe
container.innerHTML = DOMPurify.sanitize(userHtml);
div.innerHTML = escapeHtml(userText);

// ── Ternary with only literal HTML branches (ternary guard fires) ─────────────

// Both branches are string literals — no user data involved.
// The whole ternary must be on ONE line; multi-line ternaries are scanned
// line-by-line so the '?' only appears on the continuation line, not the
// innerHTML assignment line.
badge.innerHTML = (isAdmin ? '<span class="admin">Admin</span>' : '<span>User</span>');
icon.innerHTML  = (isActive ? '<i class="on"></i>' : '<i class="off"></i>');
empty.innerHTML = (count === 0 ? '<p class="empty">No items.</p>' : '<p>Has items.</p>');

// ── Template literals where all interpolations are sanitized ──────────────────

// Every ${} uses a function from _SAFE_FUNCS or a method call — safe
item.innerHTML = `<li class="entry">${escapeHtml(entry.title)}</li>`;
row.innerHTML  = `<td>${DOMPurify.sanitize(cell.value)}</td>`;
