<?php
require_once "session_init.php";
session_destroy();
header("Location: login.php");
exit;
