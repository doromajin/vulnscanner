<?php
/**
 * Negative: 2-hop and 3-hop sanitization — tainted var is sanitized into a NEW
 * variable; echo outputs the clean variable, not the tainted one.
 *
 * XSS-008 Pass 2 checks whether any *tainted variable name* appears in the
 * echo expression.  $raw stays tainted, but $esc (the echo target) was never
 * added to the tainted set — no finding expected.
 */

// 2-hop: superglobal → $raw (tainted) → $esc (clean) → echo $esc
$raw = $_GET["name"];
$esc = htmlspecialchars($raw, ENT_QUOTES, "UTF-8");
echo $esc;

// 3-hop: superglobal → $raw2 → $stripped → $safe → echo $safe
$raw2   = $_POST["comment"];
$stripped = strip_tags($raw2);
$safe   = htmlentities($stripped, ENT_QUOTES, "UTF-8");
echo "<p>" . $safe . "</p>";

// Sanitized, then assigned to a display variable
$input   = $_GET["q"];
$encoded = htmlspecialchars($input);
$display = $encoded;
echo $display;
?>
