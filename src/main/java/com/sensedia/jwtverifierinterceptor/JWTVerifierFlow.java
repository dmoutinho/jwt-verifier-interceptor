package com.sensedia.jwtverifierinterceptor;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
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
	
	//java -cp jwt-verifier-interceptor-1.0.0-jar-with-dependencies.jar com.sensedia.jwtverifierinterceptor.JWTVerifierFlow 
	public static void main(String[] args) {
		try {
			JWTVerifierFlow jwt = new JWTVerifierFlow();
			jwt.jwtVerifier(jwt.getRSAPublicKey(pk),token);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
		
}