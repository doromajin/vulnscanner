<?php
/**
 * Negative: sanitizing function applied inline at the echo point.
 *
 * The tainted variable ($raw) appears inside a sanitizer call in the echo
 * expression itself.  XSS-008 Pass 2 now checks whether the entire echo
 * expression starts with a sanitizing function before firing.
 */

// htmlspecialchars wraps the tainted var inline
$raw = $_GET["name"];
echo htmlspecialchars($raw, ENT_QUOTES, "UTF-8");

// htmlentities variant
$body = $_POST["body"];
echo htmlentities($body, ENT_QUOTES, "UTF-8");

// intval at echo point — numeric output cannot introduce HTML
$page = $_GET["page"];
echo intval($page);

// strip_tags inline
$title = $_POST["title"];
echo strip_tags($title);

// esc_html (WordPress core)
$label = $_GET["label"];
echo esc_html($label);
?>
