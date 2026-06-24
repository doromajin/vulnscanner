# Pull Request

## Title
`stats: replace innerHTML with DOM API in loadPackages()`

---

## Body

### Summary

Replace the `innerHTML` template-literal assignment in `loadPackages()` with
explicit DOM construction using `insertRow()` / `insertCell()` / `textContent`.

```diff
-                tbody.innerHTML = data.packages.map(p =>
-                    `<tr><td>${p.name}</td><td>${p.count}</td></tr>`
-                ).join("");
+                tbody.replaceChildren();
+                for (const { name, count } of data.packages) {
+                    const tr = tbody.insertRow();
+                    tr.insertCell().textContent = name;
+                    tr.insertCell().textContent = count;
+                }
```

### Motivation

`innerHTML` interprets its argument as HTML markup. When combined with data
from an API response, this creates a structural dependency between the server's
output validation and the client's rendering safety.

In the current implementation the `/api/v1/top-packages` endpoint returns
package names that were originally submitted through `BuildRequest.packages`,
which Pydantic validates against `STRING_PATTERN = r"^[\w.,-]*$"`. That
pattern excludes `<`, `>`, `"`, `&`, and all other HTML-special characters,
so the page is not exploitable today.

However the `innerHTML` pattern is fragile by nature:

- A future relaxation of the package-name pattern (e.g. allowing `+` or `/`
  for custom feeds) would immediately open an XSS vector with no warning.
- Any data path that bypasses `BuildRequest` validation — a direct Redis
  write, a future admin endpoint, a migration script — would make the page
  exploitable without touching `stats.html`.
- Static analysis tools and security scanners will flag `innerHTML` as a
  finding in perpetuity, adding noise to every future audit.

Replacing `innerHTML` with `textContent` removes the HTML-injection surface
entirely, regardless of what values the API returns.

### Changes

| File | Change |
|------|--------|
| `asu/templates/stats.html` | `loadPackages()`: `innerHTML` → `insertRow` / `insertCell` / `textContent` |

**No behaviour change.** The rendered table is identical; only the mechanism
of constructing the DOM nodes differs.

### Testing

```
# Start the development server and open /stats in a browser.
# Verify the "Top Packages" table renders correctly.
# Verify that the branch <select> filter still updates the table.
```

Automated: no new tests required — the existing integration test suite covers
the `/api/v1/top-packages` endpoint response format, which is unchanged.

### References

- [MDN: Element.innerHTML — Security considerations](https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML#security_considerations)
- [CWE-79: Improper Neutralization of Input During Web Page Generation (XSS)](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP: DOM Based XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
