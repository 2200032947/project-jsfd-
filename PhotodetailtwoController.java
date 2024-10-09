package com.example.demo.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
@Controller
public class PhotodetailtwoController {
	@GetMapping("/photodetailtwo")
	public String getMonuments() {
		return "photodetailtwo";
	}


}
