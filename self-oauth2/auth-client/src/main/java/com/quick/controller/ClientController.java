package com.quick.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.reactive.function.client.WebClient;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

@Controller
public class ClientController {

    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    @Autowired
    private WebClient webClient;

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @GetMapping("/home")
    public String home(Model model, @AuthenticationPrincipal OAuth2User oauth2User) {
        model.addAttribute("username", oauth2User.getName());
        model.addAttribute("attributes", oauth2User.getAttributes());
        return "home";
    }

    @GetMapping("/products")
    public String getProducts(Model model, OAuth2AuthenticationToken authentication, HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return "No session found";
        }
        // 验证sessionID和是不是浏览器cookie中的CLIENT_SESSION
        System.out.println("Session ID = " + session.getId());

        OAuth2AuthorizedClient authorizedClient =
                authorizedClientService.loadAuthorizedClient(
                        authentication.getAuthorizedClientRegistrationId(),
                        authentication.getName());

        String products = webClient
                .get()
                .uri("http://localhost:8081/api/products")
                .attributes(oauth2AuthorizedClient(authorizedClient))
                .retrieve()
                .bodyToMono(String.class)
                .block();

        model.addAttribute("products", products);
        return "products";
    }

    @GetMapping("/userinfo")
    public String getUserInfo(Model model, OAuth2AuthenticationToken authentication) {
        OAuth2AuthorizedClient authorizedClient =
                authorizedClientService.loadAuthorizedClient(
                        authentication.getAuthorizedClientRegistrationId(),
                        authentication.getName());

        String userInfo = webClient
                .get()
                .uri("http://localhost:8081/api/user/info")
                .attributes(oauth2AuthorizedClient(authorizedClient))
                .retrieve()
                .bodyToMono(String.class)
                .block();

        model.addAttribute("userInfo", userInfo);
        return "userinfo";
    }

    @GetMapping("/admin")
    public String getAdminDashboard(Model model, OAuth2AuthenticationToken authentication) {
        if (authentication == null) {
            model.addAttribute("error", "未登录，请先登录");
            return "redirect:/login";
        }

        OAuth2AuthorizedClient authorizedClient =
                authorizedClientService.loadAuthorizedClient(
                        authentication.getAuthorizedClientRegistrationId(),
                        authentication.getName());

        if (authorizedClient == null) {
            model.addAttribute("error", "未找到授权信息");
            return "admin";
        }

        OAuth2AccessToken accessToken = authorizedClient.getAccessToken();

        // 使用RestTemplate调用资源服务器的API
        RestTemplate restTemplate = new RestTemplate();

        // 设置Authorization头
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken.getTokenValue());

        HttpEntity<String> entity = new HttpEntity<>(headers);

        try {
            ResponseEntity<String> response = restTemplate.exchange(
                    "http://localhost:8081/api/admin/dashboard",
                    HttpMethod.GET,
                    entity,
                    String.class
            );

            if (response.getStatusCode() == HttpStatus.OK) {
                model.addAttribute("adminData", response.getBody());
                model.addAttribute("status", "success");
            } else if (response.getStatusCode() == HttpStatus.FORBIDDEN) {
                model.addAttribute("error", "权限不足，需要ADMIN角色");
            } else {
                model.addAttribute("error", "API返回状态码: " + response.getStatusCode());
            }
        } catch (Exception e) {
            model.addAttribute("error", "调用API失败: " + e.getMessage());
        }

        return "admin";
    }
}
