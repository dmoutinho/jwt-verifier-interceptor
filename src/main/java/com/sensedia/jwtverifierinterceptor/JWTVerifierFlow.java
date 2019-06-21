package com.sensedia.jwtverifierinterceptor;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.impl.JWTParser;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.sensedia.interceptor.externaljar.annotation.ApiSuiteInterceptor;
import com.sensedia.interceptor.externaljar.annotation.InterceptorMethod;
import com.sensedia.interceptor.externaljar.dto.ApiCallData;
import com.sensedia.interceptor.externaljar.exception.ApiException;

@ApiSuiteInterceptor
public class JWTVerifierFlow {

	public static String token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.POstGetfAytaZS82wHcjoTyoqhMyxXiWdR7Nn7A29DNSl0EiXLdwJ6xC6AfgZWF1bOsS_TuYI3OG85AmiExREkrS6tDfTQ2B3WXlrr-wp5AokiRbz3_oB4OxG-W9KcEEbDRcZc0nH3L7LzYptiy1PtAylQGxHTWZXtGz4ht0bAecBgmpdgXMguEIcoqPJ1n3pIWk_dUZegpqx0Lka21H6XxUTxiy8OcaarA8zdnPUnV6AmNP3ecFawIFYdvJB_cm-GvpCSbr8G8y_Mllj8f4x9nBH8pQux89_6gUY618iYv7tuPWBFfEbLxtF2pZS6YC1aSfLQxeNe8djT9YjpvRZA";
	
	public static String pk = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQAB";
		
	public RSAPublicKey getRSAPublicKey(String pk) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory kf = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(pk));
        return (RSAPublicKey) kf.generatePublic(keySpecX509);		
	}

	public void jwtVerifier(RSAPublicKey publicKey, String token) {
	    Algorithm algorithm = Algorithm.RSA256(publicKey,null);
	    JWTVerifier verifier = JWT.require(algorithm)
	        .build();
		verifier.verify(token);
	}
	
	@InterceptorMethod
	public void jwtVerifier(ApiCallData apiCallData) {
	
		apiCallData.response.addHeader("before","verifier");
		
		try {
			
			jwtVerifier(getRSAPublicKey(pk),token);
		
		} catch (NoSuchAlgorithmException e) {
			
			throw new ApiException(500, "Error jwt-verifier-interceptor");
		
		} catch (InvalidKeySpecException e) {
			
			throw new ApiException(500, "Error jwt-verifier-interceptor");
			
		} catch (SignatureVerificationException e) {
			
			throw new ApiException(400, e.getMessage());
		
		}
		
		apiCallData.response.addHeader("after","verifier");
	
	}
	
	private static void getPkFromCertificate() throws Exception {
		
		try {

			String strCertificate = "-----BEGIN CERTIFICATE-----\n" + 
					"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\n" + 
					"hMwKs3vuJhM=\n" + 
					"-----END CERTIFICATE-----\n" + 
					"";
			
			InputStream stream = new ByteArrayInputStream(strCertificate.getBytes(StandardCharsets.UTF_8));

			CertificateFactory f = CertificateFactory.getInstance("X.509");
			
			X509Certificate certificate = (X509Certificate)f.generateCertificate(stream);			
			
			PublicKey pk = certificate.getPublicKey();
			
			System.out.println("RSA PK: "+new String(Base64.getEncoder().encode(pk.getEncoded())));
			
		} catch (Exception e) {
			
			e.printStackTrace();
		
		}
	
	}

	private static void testJWTVerifier() throws Exception {
		JWTVerifierFlow jwt = new JWTVerifierFlow();
		jwt.jwtVerifier(jwt.getRSAPublicKey(pk),token);
		System.out.println("OK");
	}
	
	//java -cp jwt-verifier-interceptor-1.0.0-jar-with-dependencies.jar com.sensedia.jwtverifierinterceptor.JWTVerifierFlow 
	public static void main(String[] args) {

		try {
			
			getPkFromCertificate();
			
			//testJWTVerifier();
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}
		
}
