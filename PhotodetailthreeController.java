package com.example.demo.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
@Controller
public class PhotodetailthreeController {
	@GetMapping("/photodetailthree")
	public String getMonuments() {
		return "photodetailthree";
	}

}
