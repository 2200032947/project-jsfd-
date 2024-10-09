package com.example.demo.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class MonumentController {
	@GetMapping("/monuments")
	public String getMonuments() {
		return "monuments";
	}

}

