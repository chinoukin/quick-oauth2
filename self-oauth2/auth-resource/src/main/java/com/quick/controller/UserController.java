package com.quick.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class UserController {

    @GetMapping("/userinfo")
    public Map<String, Object> userinfo(Authentication authentication) {

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
}
