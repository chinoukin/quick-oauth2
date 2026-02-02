package com.quick.controller;

import ch.qos.logback.core.net.SyslogOutputStream;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class ResourceController {

    @GetMapping("/public/hello")
    public String publicHello() {
        return "Hello from Public Resource!";
    }

//    @GetMapping("/user/info")
//    public String getUserInfo(@AuthenticationPrincipal Jwt jwt) {
//        return String.format("Hello, %s! Your roles: %s",
//                jwt.getClaimAsString("user_name"),
//                jwt.getClaimAsString("scope"));
//    }

    @GetMapping("/user/info")
    public Map<String, Object> getUserInfo(Authentication authentication) {

        OAuth2Authentication oauth2Auth = (OAuth2Authentication) authentication;

        Map<String, Object> userInfo = new HashMap<>();
        if (oauth2Auth != null && oauth2Auth.getUserAuthentication() != null) {
            // 基本用户信息
            userInfo.put("sub", authentication.getName());
            userInfo.put("user_name", authentication.getName());
            userInfo.put("name", authentication.getName());

            // 添加权限信息
            userInfo.put("authorities", authentication.getAuthorities());

            // 添加客户端信息
            if (oauth2Auth.getOAuth2Request() != null) {
                userInfo.put("client_id", oauth2Auth.getOAuth2Request().getClientId());
                userInfo.put("scope", oauth2Auth.getOAuth2Request().getScope());
            }

            // 添加其他声明
            userInfo.put("active", true);
        }

        return userInfo;
    }

    @GetMapping("/admin/dashboard")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminDashboard() {
        return "Welcome to Admin Dashboard!";
    }

    @GetMapping("/products")
    public String getProducts() {
        return "Product List: [iPhone, MacBook, iPad]";
    }


}