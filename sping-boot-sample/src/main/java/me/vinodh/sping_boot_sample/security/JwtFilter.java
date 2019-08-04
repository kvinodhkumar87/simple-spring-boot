package me.vinodh.sping_boot_sample.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

import me.vinodh.sping_boot_sample.services.JwtTokenService;

public class JwtFilter extends GenericFilterBean {

	private JwtTokenService tokenService;

	public JwtFilter(JwtTokenService tokenService) {
		this.tokenService = tokenService;
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest request = (HttpServletRequest) req;
		HttpServletResponse response = (HttpServletResponse) resp;
		String token = request.getHeader("Authorization");

		if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
			response.setStatus(HttpServletResponse.SC_OK);
			return;
		}

		if (allowRequestWithoutToken(request)) {
			response.setStatus(HttpServletResponse.SC_OK);
			chain.doFilter(request, response);
		} else {
			if (token == null || !tokenService.isTokenValid(token)) {
				response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			} else {
				Authentication auth = token != null ? tokenService.getAuthentication(token) : null;
				SecurityContextHolder.getContext().setAuthentication(auth);
				chain.doFilter(request, response);
			}
		}

	}

	public boolean allowRequestWithoutToken(HttpServletRequest request) {
		if (request.getRequestURI().contains("/api")) {
			return false;
		}
		return true;
	}
}
