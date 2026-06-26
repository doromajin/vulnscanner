<?php
// XSS-008: 1-hop taint — superglobal assigned to variable, then echoed

// Pattern 1: concatenation in echo
$username = $_GET['user'];
echo "<h1>Welcome, " . $username . "</h1>";

// Pattern 2: string interpolation in echo
$title = $_POST['title'];
echo "<title>$title</title>";
?>
