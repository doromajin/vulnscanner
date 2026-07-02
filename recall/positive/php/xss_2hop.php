<?php
// 2-hop taint: $_GET → $raw → $display → echo
// XSS-008 (regex) misses this because $display is not directly from $_GET
$raw = $_GET['user'];
$display = $raw;
echo "<h1>Hello, " . $display . "</h1>";
