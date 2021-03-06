package com.infotech.jwt.controller;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.infotech.jwt.model.User;
import com.infotech.jwt.security.JwtTokenProvider;

import javax.annotation.security.RolesAllowed;

@RestController
public class LoginController {

	@Autowired
	JwtTokenProvider jwtTokenProvider;
	
	@PostMapping("/login")
	public ResponseEntity<String> login(@RequestBody User user) {
		String key = "roles";
		List<String> roles = Arrays.asList("ADMIN", "DEVELOPER", "NORMAL");
		Map<String, List<String>> maps = new HashMap<>();
		maps.put(key, roles);
		String token = jwtTokenProvider.createToken(maps);
		System.out.println("Token: "+token);
		HttpHeaders headers = new HttpHeaders();
		headers.set("authentication", token);
		return new ResponseEntity<String>(token, headers, HttpStatus.CREATED);
	}
	
	@GetMapping("/test")
	//@Secured("ROLE_DEVELOPER")
	//@PreAuthorize("hasRole('ROLE_ADMIN')") // hasRole, hasAnyRole, hasAuthority, hasAnyAuthority
	//@RolesAllowed("ROLE_NORMAL")
	public String test() {
		return "test success..";
	}
}
