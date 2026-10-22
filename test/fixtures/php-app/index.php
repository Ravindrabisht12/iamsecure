<?php
require 'vendor/autoload.php';

$page = $_GET['page'];
include("pages/" . $page . ".php");

$id = $_GET['id'];
$result = mysqli_query($conn, "SELECT * FROM orders WHERE id = " . $id);

echo "Hello " . $_GET['name'];
echo "Safe " . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');

$prefs = unserialize($_COOKIE['prefs']);
system("convert " . $_POST['file'] . " out.png");
$hash = md5($_POST['password']);
