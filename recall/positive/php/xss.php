<?php
// XSS-005: direct echo of superglobal — user input written to output without encoding
echo $_GET['name'];
echo $_POST['comment'];
?>
