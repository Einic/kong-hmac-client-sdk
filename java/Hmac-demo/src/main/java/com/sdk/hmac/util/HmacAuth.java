package com.tencent.netplat.demo.hmac.util;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * @author gavin
 * @version 1.0
 * @date 2020/4/5
 **/
public class HmacAuth {
    /**
     * username
     */
    private String userName;

    /**
     * secret
     */
    private String secret;

    /**
     * Encrypted content
     */
    private String body;

    /**
     * hmac encryption algorithm
     */
    private String hmacAlgo = "HmacSHA256";

    public HmacAuth(String userName, String secret, String body) {
        this.userName = userName;
        this.secret = secret;
        this.body = body;
    }

    public HmacAuth(String userName, String secret, String body, String hmacAlgo){
        this.userName = userName;
        this.secret = secret;
        this.body = body;
        this.hmacAlgo = hmacAlgo;
    }

    /**
      * Generate HmacAuth encrypted authentication header
      * @return certified header
      * @throws NoSuchAlgorithmException The encryption algorithm is not supported
      * @throws InvalidKeyException Encryption secret exception
     */
    public Map<String, String> genAuthHead() throws NoSuchAlgorithmException, InvalidKeyException {
        // Generate sha256 encrypted string of body
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] digestHash = digest.digest(this.body.getBytes(StandardCharsets.UTF_8));
        String bodyHash = Base64.getEncoder().encodeToString(digestHash);
        String bodyDigest = String.format("SHA-256=%s", bodyHash);

        // Generate the current GMT time, note that the format cannot be changed, it must be like: Wed, 14 Aug 2019 09:09:28 GMT
        SimpleDateFormat df = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss 'GMT'");
        df.setTimeZone(TimeZone.getTimeZone("GMT"));
        String timeNow = df.format(new Date());

        // Assemble the data to be signed
        String signData = String.format("date: %s\ndigest: %s", timeNow, bodyDigest);

        // Generate hmac signature
        Mac hmac = Mac.getInstance(this.hmacAlgo);
        hmac.init(new SecretKeySpec(this.secret.getBytes(StandardCharsets.UTF_8), this.hmacAlgo));
        byte[] hmacHash = hmac.doFinal(signData.getBytes(StandardCharsets.UTF_8));
        String hmacSign = Base64.getEncoder().encodeToString(hmacHash);

        // Assemble headers
        Map<String, String> header = new HashMap<>(3);
        String auth = String.format("hmac username=\"%s\", algorithm=\"hmac-sha256\", headers=\"date digest\", signature=\"%s\"", this.userName, hmacSign);
        header.put("Authorization", auth);
        header.put("Digest", bodyDigest);
        header.put("Date", timeNow);
        return header;
    }
}
