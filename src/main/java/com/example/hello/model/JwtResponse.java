package com.example.hello.model;

public class JwtResponse {

	private final String jwtToken;

	public JwtResponse(String jwtToken) {
		super();
		this.jwtToken = jwtToken;
	}

	public String getJwtToken() {
		return jwtToken;
	}	
	
}
