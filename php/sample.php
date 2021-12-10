<?php
include("hmac_auth.php");

// Please modify according to the actual situation
$username = '<hmac account>';
$secret = '<hmac secret>';
$url = '<Interface address with hmac authentication>';
 
$params = json_encode(array(
    'params' => array(
        'foo' => 'bar'
    ),
));
$headers = HmacAuth::get_auth_header($username, $secret);
 
// ask
$ch = curl_init($url);
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, $params);
 
$result = curl_exec($ch);
echo $result;
