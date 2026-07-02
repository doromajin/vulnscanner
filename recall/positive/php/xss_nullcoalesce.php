<?php
// Null-coalescing taint propagation: XSS-008 handles the first hop ($name),
// but misses the second hop ($display = $name ?? 'guest')
$name = $_GET['name'] ?? null;
$display = $name ?? 'guest';
echo "<p>Welcome, " . $display . "</p>";
