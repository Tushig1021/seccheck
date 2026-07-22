<?php
require_once "config.php";
require_once __DIR__ . "/vendor/autoload.php";

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

// sends an email and returns true/false rather than throwing,
// so callers can decide how to handle a failure without a try/catch every time
function sendEmail($toAddress, $subject, $bodyText) {
    $mail = new PHPMailer(true);

    try {
        $mail->isSMTP();
        $mail->Host = SMTP_HOST;
        $mail->SMTPAuth = true;
        $mail->Username = SMTP_USER;
        $mail->Password = SMTP_PASS;
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port = SMTP_PORT;

        $mail->setFrom(SMTP_USER, "SecCheck");
        $mail->addAddress($toAddress);

        $mail->Subject = $subject;
        $mail->Body = $bodyText;

        $mail->send();
        return true;
    } catch (Exception $e) {
        error_log("Email send failed to $toAddress: " . $mail->ErrorInfo);
        return false;
    }
}
