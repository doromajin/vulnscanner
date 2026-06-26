<?php
// SQL-001 / SQL-002: SQL injection via $_GET concatenation
$conn = mysqli_connect("localhost", "root", "", "appdb");
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = " . $id;
mysqli_query($conn, $query);
?>
