package com.github.oauth.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import javax.servlet.http.HttpServletResponse;

@Controller
public class UserController {

    @GetMapping("/user/info")
    public String userInfo(@AuthenticationPrincipal OAuth2User principal, Model model) {
        model.addAttribute("username", principal.getAttribute("login"));
        model.addAttribute("avatar_url", principal.getAttribute("avatar_url"));
        return "user-info";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

}
