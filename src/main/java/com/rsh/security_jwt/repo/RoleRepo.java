package com.rsh.security_jwt.repo;

import org.springframework.data.jpa.repository.JpaRepository;

import com.rsh.security_jwt.domain.Role;

public interface RoleRepo extends JpaRepository<Role, Long>{

	Role findByName(String name);
	
}
