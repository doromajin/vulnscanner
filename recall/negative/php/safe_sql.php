<?php
// Negative: PHP SQL patterns using prepared statements — SQL-004 requires
// `$sql = "SELECT..." . $var` concatenation which is absent here.

$pdo = new PDO("mysql:host=localhost;dbname=app", "dbuser", "dbpass");

// PDO with positional parameters
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET["id"]]);

// PDO with named parameters
$stmt = $pdo->prepare("SELECT * FROM users WHERE name = :name AND status = :status");
$stmt->execute([":name" => $_GET["name"], ":status" => "active"]);

// MySQLi prepared statement
$mysqli = new mysqli("localhost", "dbuser", "dbpass", "app");
$ps = $mysqli->prepare("SELECT email FROM accounts WHERE uid = ?");
$ps->bind_param("i", $_GET["uid"]);
$ps->execute();
?>
