<?php
/**
   Hmac certification class by Cal
**/
class HmacAuth
{
    public static function get_auth_header($username = '', $secret = '', $body = '')
    {
        // Generate sha256 encrypted string of body
        $body_digest = 'SHA-256=' . base64_encode(hash('sha256', $body, true));
        // Generate the current GMT time, note that the format cannot be changed, it must be like: Wed, 14 Aug 2019 09:09:28 GMT
        $gmt_time = gmdate('D, d M Y H:i:s T');
        // Production signature
        $sinature = base64_encode(hash_hmac('sha256', "date: {$gmt_time}\ndigest: {$body_digest}", $secret, true));
        $headers = array(
            "Authorization: hmac username=\"{$username}\", algorithm=\"hmac-sha256\", headers=\"date digest\", signature=\"{$sinature}\"",
            "Digest: {$body_digest}",
            "Date: $gmt_time",
            "Content-Type: application/json",
        );
        return $headers;
    }
}
