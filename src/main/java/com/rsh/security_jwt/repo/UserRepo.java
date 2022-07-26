package com.rsh.security_jwt.repo;

import org.springframework.data.jpa.repository.JpaRepository;

import com.rsh.security_jwt.domain.User;

public interface UserRepo extends JpaRepository<User, Long> {

	User findByUsername(String username);
	
}
