<?php
// DESER-004: PHP unserialize() — object injection / RCE risk
$data = $_POST['payload'];
$obj = unserialize($data);
var_dump($obj);
?>
