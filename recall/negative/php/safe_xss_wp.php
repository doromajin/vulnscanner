<?php
/**
 * Negative: WordPress sanitization functions assigned to intermediate variables.
 *
 * sanitize_text_field, wp_strip_all_tags, esc_url, and esc_textarea are all
 * safe sanitizers now included in _PHP_XSS_CLEAN_RE.  Assignments through
 * these functions must not add the variable to the tainted set.
 */

// sanitize_text_field: strips HTML tags, extra whitespace, invalid UTF-8
$title = sanitize_text_field($_POST["title"]);
echo "<h1>" . $title . "</h1>";

// wp_strip_all_tags: removes HTML/PHP tags
$content = wp_strip_all_tags($_POST["content"]);
echo $content;

// esc_url: encodes URLs for safe use in href / src attributes
$link = esc_url($_GET["redirect"]);
echo '<a href="' . $link . '">Go</a>';

// esc_textarea: htmlspecialchars variant for textarea values
$bio = esc_textarea($_POST["bio"]);
echo '<textarea name="bio">' . $bio . '</textarea>';
?>
