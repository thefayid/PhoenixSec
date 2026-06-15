<?php
function queryUser($conn, $userId) {
    $stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->bind_param("s", $userId);
    $stmt->execute();
}

function pingHost($host) {
    system("ping -c 3 " . escapeshellarg($host));
}
?>
