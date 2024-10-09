package com.example.demo.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
@Controller
public class CulturedetailtwoController {
	@GetMapping("/culturedetailtwo")
	public String getculturedetailtwo() {
		return "culturedetailtwo";
	}


}
