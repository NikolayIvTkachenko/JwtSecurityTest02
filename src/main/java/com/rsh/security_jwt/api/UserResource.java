package com.rsh.security_jwt.api;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.servlet.Servlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.rsh.security_jwt.domain.Role;
import com.rsh.security_jwt.domain.User;
import com.rsh.security_jwt.dto.RoleToUserForm;
import com.rsh.security_jwt.service.UserService;




@RestController
@RequestMapping(value = "/api")
public class UserResource {
	
	private final UserService userService;

	@Autowired
	public UserResource(UserService userService) {
		super();
		this.userService = userService;
	}
	
	@GetMapping(value = "/users")
	public ResponseEntity<List<User>> getUsers(){
		return ResponseEntity.ok().body(userService.getUsers());
	}

	@PostMapping(value = "/users/save")
	public ResponseEntity<User> saveUser(@RequestBody User user){
		URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user/save").toUriString());
		return ResponseEntity.created(uri).body(userService.saveUser(user));
	}
	
	@PostMapping(value = "/role/save")
	public ResponseEntity<Role> saveRole(@RequestBody Role role){
		URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/role/save").toUriString());
		return ResponseEntity.created(uri).body(userService.saveRole(role));
	}
	
	@PostMapping(value = "/role/addtouser")
	public ResponseEntity<?> addRoleToUser(@RequestBody RoleToUserForm form){
		userService.addRoleToUser(form.getUsername(), form.getRolename());
		return ResponseEntity.ok().build();
	}
	
	@GetMapping(value = "/token/refresh")
	public void refreshToken(@RequestBody HttpServletRequest request, HttpServletResponse response) throws IOException{
		
		String autorizationHeaderString = request.getHeader(HttpHeaders.AUTHORIZATION);
		
		if(autorizationHeaderString != null && autorizationHeaderString.startsWith("Bearer ")) {
			try {
				
				String refresh_token = autorizationHeaderString.substring("Bearer ".length());
				Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());
				JWTVerifier verifier = JWT.require(algorithm).build();
				DecodedJWT decodedJWT = verifier.verify(refresh_token);
				String username = decodedJWT.getSubject();
				
				User user = userService.getUser(username);
				
				
				String access_token = JWT.create()
						.withSubject(user.getUsername())
						.withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
						.withIssuer(request.getRequestURI().toString())
						.withClaim("roles", user.getRoles().stream().map(Role::getName).collect(Collectors.toList()))
						.sign(algorithm);
				
				
				Map<String, String> tokensMap = new HashMap<>();
				tokensMap.put("access_token", access_token);
				tokensMap.put("refresh_token", refresh_token);
				response.setContentType(MediaType.APPLICATION_JSON_VALUE);
				new ObjectMapper().writeValue(response.getOutputStream(), tokensMap);
				
				
			}catch (Exception e) {
				
				response.setHeader("error", e.getMessage());
				response.sendError(HttpStatus.FORBIDDEN.value());
				response.setContentType(MediaType.APPLICATION_JSON_VALUE);
				
				Map<String, String> error = new HashMap<>();
				error.put("error_message", e.getMessage());
				
				new ObjectMapper().writeValue(response.getOutputStream(), error);
			}
			
		} else {
			throw new RuntimeException("Refresh token is missing!");
		}
	}
}
