// Negative: JS/DOM XSS-safe patterns — must produce zero active findings.

// textContent / innerText: no HTML parsing, always safe
document.getElementById("output").textContent = userInput;
element.innerText = userData;

// createTextNode — no HTML parsing, safe DOM insertion
const textNode = document.createTextNode(userInput);
parent.appendChild(textNode);

// innerHTML with explicit sanitizer function call
// Rule: any function application is treated as safer than a bare variable reference
element.innerHTML = DOMPurify.sanitize(userInput);
el.innerHTML = escapeHtml(content);

// innerHTML with a quoted string literal — no interpolation, always safe
container.innerHTML = '<div class="empty-state">No results found.</div>';

// Template literal with no ${} interpolation — always safe
el.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg"><circle r="10"/></svg>`;

// Template literal where every interpolation is a safe function call
el.innerHTML = `<p>${escapeHtml(title)}</p>`;
