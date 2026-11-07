<?php
// SYNTHETIC FIXTURE - fake values for scanner testing only, not real credentials.
// Vulnerable sample: hardcoded mail provider API key.
define('MAIL_API_KEY', 'SENDGRID_KEY_REDACTED');

function mailer_config(): array {
    return ['key_configured' => MAIL_API_KEY !== ''];
}