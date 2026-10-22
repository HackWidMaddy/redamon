<?php
// Minimal app that uses a session, so upload-progress tracking is in play for a
// multipart POST that carries the PHP_SESSION_UPLOAD_PROGRESS field.
session_start();
header('Content-Type: text/plain');
echo "php2shell guinea pig\n";
echo 'PHP ' . PHP_VERSION . "\n";
echo "session.upload_progress.enabled=" . ini_get('session.upload_progress.enabled') . "\n";
