package me.vinodh.sping_boot_sample.services;

import java.io.UnsupportedEncodingException;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

@Service
public class JwtTokenService {

	private static final Logger logger = LoggerFactory.getLogger(JwtTokenService.class);

	public static final String TOKEN_SECRET = "sendthru21232";

	@Autowired
	private CustomUserDetailsService userDetailsService;

	public String createToken(String email) {
		try {
			Algorithm algorithm = Algorithm.HMAC256(TOKEN_SECRET);
			String token = JWT.create().withClaim("email", email).withClaim("createdAt", new Date()).sign(algorithm);
			return token;
		} catch (UnsupportedEncodingException e) {
			logger.error("Exception occurred while creating token", e);
		} catch (JWTCreationException e) {
			logger.error("Exception occurred while creating token", e);
		}
		return null;
	}

	public Authentication getAuthentication(String token) {
		UserDetails userDetails = this.userDetailsService.loadUserByUsername(getEmailFromToken(token));
		return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
	}

	public String getEmailFromToken(String token) {
		try {
			Algorithm algorithm = Algorithm.HMAC256(TOKEN_SECRET);
			JWTVerifier verifier = JWT.require(algorithm).build();
			DecodedJWT jwt = verifier.verify(token);
			return jwt.getClaim("email").asString();
		} catch (UnsupportedEncodingException e) {
			logger.error("Exception occurred while getting memberId from token", e);
			return null;
		} catch (JWTVerificationException e) {
			logger.error("Exception occurred while getting memberId from token", e);
			return null;
		}
	}

	public boolean isTokenValid(String token) {
		String email = this.getEmailFromToken(token);
		return email != null;
	}
}
