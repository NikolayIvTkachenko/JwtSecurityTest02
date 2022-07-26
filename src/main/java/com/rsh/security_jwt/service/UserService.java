package com.rsh.security_jwt.service;

import java.util.List;

import com.rsh.security_jwt.domain.Role;
import com.rsh.security_jwt.domain.User;


public interface UserService {
	
	User saveUser(User user);
	Role saveRole(Role role);
	void addRoleToUser(String username, String roleName);

	User getUser(String username);

	List<User> getUsers();
	

}
