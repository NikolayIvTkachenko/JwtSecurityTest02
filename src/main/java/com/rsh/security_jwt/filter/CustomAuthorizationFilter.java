package com.rsh.security_jwt.filter;


import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.fasterxml.jackson.databind.ObjectMapper;


public class CustomAuthorizationFilter extends OncePerRequestFilter{

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		if(request.getServletPath().equals("/api/login") || request.getServletPath().equals("/api/token/refresh")) {
			filterChain.doFilter(request, response);
			
		} else {
			String autorizationHeaderString = request.getHeader(HttpHeaders.AUTHORIZATION);
			if(autorizationHeaderString != null && autorizationHeaderString.startsWith("Bearer ")) {
				
				try {
					
					String token = autorizationHeaderString.substring("Bearer ".length());
					Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
					JWTVerifier verifier = JWT.require(algorithm).build();
					DecodedJWT decodedJWT = verifier.verify(token);
					String username = decodedJWT.getSubject();
					List<String> roleStrings = decodedJWT.getClaim("roles").asList(String.class);
					
					Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
					
					roleStrings.stream().forEach(role ->  {
						authorities.add(new SimpleGrantedAuthority(role));
					});

					
					UsernamePasswordAuthenticationToken authenticationToken 
						= new UsernamePasswordAuthenticationToken(username, null, authorities);
					SecurityContextHolder.getContext().setAuthentication(authenticationToken);
					
					filterChain.doFilter(request, response);
					
					
				}catch (Exception e) {
					
					response.setHeader("error", e.getMessage());
					response.sendError(HttpStatus.FORBIDDEN.value());
					response.setContentType(MediaType.APPLICATION_JSON_VALUE);
					
					Map<String, String> error = new HashMap<>();
					error.put("error_message", e.getMessage());
					
					new ObjectMapper().writeValue(response.getOutputStream(), error);
				}
				
			} else {
				filterChain.doFilter(request, response);
			}
		}
		
	}

}
