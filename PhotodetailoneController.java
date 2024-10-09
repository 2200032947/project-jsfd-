package com.example.demo.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class PhotodetailoneController {
	@GetMapping("/photodetailone")
	public String getMonuments() {
		return "photodetailone";
	}

}
