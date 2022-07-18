package com.rsh.security_jwt.dto;

public class RoleToUserForm {

	private String username;
	private String rolename;
	
	
	public RoleToUserForm() {
		super();
	}


	public RoleToUserForm(String username, String rolename) {
		super();
		this.username = username;
		this.rolename = rolename;
	}


	public String getUsername() {
		return username;
	}


	public void setUsername(String username) {
		this.username = username;
	}


	public String getRolename() {
		return rolename;
	}


	public void setRolename(String rolename) {
		this.rolename = rolename;
	}
	
	
}
