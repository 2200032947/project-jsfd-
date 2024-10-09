package com.example.demo.web;

import java.util.Objects;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.ModelAndView;

import com.example.demo.model.Admin;
import com.example.demo.service.AdminService;

@Controller
public class AdminController {
	
	@Autowired
	private AdminService adminService;
	
	  @GetMapping("/admin")
      
	    public ModelAndView admin() {
	     ModelAndView mav = new ModelAndView("admin");
	        mav.addObject("admin", new Admin());
	        return mav;
	    }
	 
	    @PostMapping("/admin")
	    public String admin(@ModelAttribute("user") Admin admin ) {
	    
	     Admin oauthUser = adminService.login(admin.getUsername(), admin.getPassword());
	    
	 
	     System.out.print(oauthUser);
	     if(Objects.nonNull(oauthUser))
	     {
	  
	     return "redirect:/adminnext";
	    
	    
	     } else {
	     return "redirect:/admin";
	    
	    
	     }
	 
	}
	    
	    @PostMapping({"/logout"})
	    public String logoutDo(HttpServletRequest request,HttpServletResponse response)
	    {
	    
	  
	        return "redirect:/admin";
	    }

}
