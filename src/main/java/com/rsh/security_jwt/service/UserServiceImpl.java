package com.rsh.security_jwt.service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.transaction.Transactional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.rsh.security_jwt.domain.Role;
import com.rsh.security_jwt.domain.User;
import com.rsh.security_jwt.repo.RoleRepo;
import com.rsh.security_jwt.repo.UserRepo;

@Service
@Transactional
//@Slf4j
public class UserServiceImpl implements UserService, UserDetailsService {

	private final UserRepo userRepo;
	private final RoleRepo rolerepo;
	private final PasswordEncoder passwordEncoder;
	
	@Autowired
	public UserServiceImpl(UserRepo userRepo, RoleRepo rolerepo, PasswordEncoder passwordEncoder) {
		this.userRepo = userRepo;
		this.rolerepo = rolerepo;
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public User saveUser(User user) {
		user.setPassword(passwordEncoder.encode(user.getPassword()));
		return userRepo.save(user);
	}

	@Override
	public Role saveRole(Role role) {
		
		return rolerepo.save(role);
	}

	@Override
	public void addRoleToUser(String username, String roleName) {
		User user = userRepo.findByUsername(username);
		Role role = rolerepo.findByName(roleName);
		
		user.getRoles().add(role);
		
	}

	@Override
	public User getUser(String username) {
		
		return userRepo.findByUsername(username);
	}

	@Override
	public List<User> getUsers() {
		
		return userRepo.findAll();
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User user = userRepo.findByUsername(username);
		if(user == null) {
			//log
			throw new UsernameNotFoundException("User not found in the database");
		} else {
			//log
		}
		Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
		user.getRoles().forEach(role -> {
			authorities.add(new SimpleGrantedAuthority(role.getName()));
		});
		return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), authorities);
	}


}
