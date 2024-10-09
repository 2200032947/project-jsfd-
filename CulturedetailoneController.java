package com.example.demo.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
@Controller
public class CulturedetailoneController {
	@GetMapping("/culturedetailone")
	public String getculturedetailtone() {
		return "culturedetailone";
	}

}
