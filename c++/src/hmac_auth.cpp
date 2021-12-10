/*
 ******************************************************************************************************
 Copyright 1998 - 2021 Tencent. All Rights Reserved
 file: hmac_auth.cpp
 date: 2020-04-02
 author: steven
 desc: HMAC authentication implementation
 detail:
 1. The input body is encrypted with SHA-256 and then encoded with base64 to obtain a string of readable encrypted string digest
 2. Add "SHA-256=" before digest, and then spell it into date:<GMT time>\ndigest:<digest>
  Format string 
 3. HMAC encryption of the secret and the content obtained in the second step to obtain the signature sign
 4. Add the following format content to the HTTP request header
  Date: <GMT time>
  Digest: <digest>
  Authorization: hmac username=<user>, algorithm="hmac-sha256", headers="date
 digest", signature=<sign>
 *******************************************************************************************************
*/
#include "hmac_auth.h"

#include <openssl/hmac.h>
#include <openssl/sha.h>

#include <cstring>
#include <ctime>
#include <iostream>
#include <sstream>
#include <string>

HMACAuth::HMACAuth(const std::string &user, const std::string &secret, const std::string &body)
    : user_(user), secret_(secret), body_(body) {}

int HMACAuth::getAuthInfo(AuthInfo* auth_info) {
  std::string date = getGMTTime();
  std::string digest = getDigest(body_);

  std::ostringstream oss;
  oss << "date: " << date << "\ndigest: " << digest;

  std::string sign = hmacEncrypt(secret_, oss.str());

  std::ostringstream auth;
  auth << "hmac username=\"" << user_
       << "\", algorithm=\"hmac-sha256\", headers=\"date digest\", signature=\"" << sign << "\"";

  auth_info->date = date;
  auth_info->digest = digest;
  auth_info->auth = auth.str();

  return 0;
}

std::string HMACAuth::base64Encode(const std::string &text) {
  static unsigned char base64_table[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  char *buf = new char[text.size() * 2];
  char *dst = buf;

  for (size_t i = 0, len = 0; i < text.size(); len += 4) {
    unsigned int c = (unsigned char)text[i++];
    c <<= 8;

    if (i < text.size()) {
      c += (unsigned char)text[i];
    }

    c <<= 8;
    ++i;

    if (i < text.size()) {
      c += (unsigned char)text[i];
    }

    ++i;

    *dst++ = base64_table[(c >> 18) & 0x3f];
    *dst++ = base64_table[(c >> 12) & 0x3f];

    if (i > (text.size() + 1)) {
      *dst++ = '=';
    } else {
      *dst++ = base64_table[(c >> 6) & 0x3f];
    }

    if (i > text.size()) {
      *dst++ = '=';
    } else {
      *dst++ = base64_table[(c >> 0) & 0x3f];
    }
  }

  *dst = '\0';

  return std::string(buf);
}

std::string HMACAuth::sha256Encrypt(const std::string &text) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  memset(hash, 0, sizeof(hash));

  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, text.c_str(), text.size());
  SHA256_Final(hash, &sha256);

  // You cannot directly use "ret=(char*)hash;" to assign hash to ret, otherwise there will be an extra character 0x01 at the end
  std::string ret(reinterpret_cast<char *>(hash), sha256.md_len);

  return ret;
}

// 1. Perform sha256 calculation on the body first
// 2. Then base64 encode the string calculated by sha256
// 3. "SHA-256=" should be added to the returned string header
std::string HMACAuth::getDigest(const std::string &body) {
  std::string sha_body = sha256Encrypt(body);
  std::string base64_body = base64Encode(sha_body);

  std::ostringstream oss;
  oss << "SHA-256=" << base64_body;

  return oss.str();
}

std::string HMACAuth::hmacEncrypt(const std::string &secret, const std::string &text) {
  unsigned char out[EVP_MAX_MD_SIZE];
  unsigned int out_size = 0;

  memset(out, 0, sizeof(out));

  HMAC_CTX ctx;
  HMAC_CTX_init(&ctx);

  HMAC_Init_ex(&ctx, secret.c_str(), secret.size(), EVP_sha256(), NULL);
  HMAC_Update(&ctx, reinterpret_cast<const unsigned char *>(text.c_str()), text.size());

  HMAC_Final(&ctx, out, &out_size);
  HMAC_CTX_cleanup(&ctx);

  std::string hmac_str(reinterpret_cast<char *>(out), out_size);
  std::string result =
      base64Encode(hmac_str);  // Do base64 encoding again after HMAC authentication so that the authenticated characters can be printed

  return result;
}

std::string HMACAuth::getGMTTime() {
  struct tm gm_time;
  time_t now = time(0);

  gmtime_r(&now, &gm_time);

  char time_buf[64];
  strftime(time_buf, sizeof(time_buf) - 1, "%a, %d %b %Y %H:%M:%S GMT", &gm_time);

  std::string ret(time_buf);
  return ret;
}
