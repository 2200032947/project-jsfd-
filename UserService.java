package com.example.demo.service;

import java.util.List;

import org.springframework.security.core.userdetails.UserDetailsService;

import com.example.demo.model.User;
import com.example.demo.web.dto.UserRegistrationDto;

public interface UserService extends UserDetailsService{
	List<User>getUsers();
	User save(UserRegistrationDto registrationDto);
	void saveUser(User user);

}
