<?php
function queryUser($conn, $userId) {
    $query = "SELECT * FROM users WHERE id = " . $userId;
    mysqli_query($conn, $query);
}

function pingHost($host) {
    system("ping -c 3 " . $host);
}
?>
