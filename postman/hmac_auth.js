/**
  * Instructions for use:
  * Copy the content of this file to postman's Pre-Request Script
  * Modify userName and secret according to the actual situation
 */

const userName = '<hmac account>';
const secret = '<hmac secret>';

const dateObj = new Date();
const gmtTime = dateObj.toGMTString();
const body = pm.request.body.raw;
const sha256 = CryptoJS.SHA256(body);
const digest = `SHA-256=${CryptoJS.enc.Base64.stringify(sha256)}`;

const sinature = CryptoJS.enc.Base64.stringify(CryptoJS.HmacSHA256(`date: ${gmtTime}\ndigest: ${digest}`, secret));

console.log(`Date: ${gmtTime}`);
console.log(`Digest: ${digest}`);
console.log(`sinature: ${sinature}`);
console.log(`Authorization: hmac username="${userName}", algorithm="hmac-sha256", headers="date digest", signature="${sinature}"`);

pm.request.headers.upsert({ key: 'Date', value: gmtTime });
pm.request.headers.upsert({ key: 'Digest', value: digest });
pm.request.headers.upsert({
    key: 'Authorization',
    value: `hmac username="${userName}", algorithm="hmac-sha256", headers="date digest", signature="${sinature}"`
});
