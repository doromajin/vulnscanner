<?php
// Negative: PHP XSS-safe output patterns.
// XSS-005 requires `echo $_GET` directly — wrapping in a function does NOT match.
// XSS-008 (1-hop) checks assignments first; sanitized assignments are removed from tainted map.

// Direct sanitization — XSS-005 regex needs bare superglobal after echo
echo htmlspecialchars($_GET["name"], ENT_QUOTES, "UTF-8");
echo htmlentities($_POST["comment"]);

// Variable sanitized at assignment time — not added to tainted map
$safe_name = htmlspecialchars($_GET["user"], ENT_QUOTES, "UTF-8");
echo $safe_name;

// Variable tainted, then re-sanitized — removed from tainted map before echo
$val = $_GET["q"];
$val = htmlentities($val);
echo $val;

// Sanitized with strip_tags
$title = strip_tags($_POST["title"]);
echo "<h1>" . $title . "</h1>";
?>
