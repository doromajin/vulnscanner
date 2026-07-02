<?php
// Function-based taint propagation: regex analyzers cannot follow
// taint across function call boundaries
function getUserName() {
    return $_GET['name'];
}

$name = getUserName();
echo "<h1>Hello, " . $name . "</h1>";
