package com.example.demo.web;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import com.example.demo.model.User;
import com.example.demo.service.UserService;


@Controller
public class AdminnextController {
	
	@Autowired
	private UserService userServiceImpl;
	
	
	@GetMapping("/adminnext")
	public String getAdminext(Model model) {
		
		List<User> userList = userServiceImpl.getUsers();
		
		model.addAttribute("adminnext", userList);
		
		
		return "adminnext";
	}

}
