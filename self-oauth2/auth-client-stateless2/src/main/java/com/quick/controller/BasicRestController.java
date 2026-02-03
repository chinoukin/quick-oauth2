package com.quick.controller;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.apache.http.client.HttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.KeyPair;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;

@RestController
public class BasicRestController {

    private final String clientId = "client-app";
    private final String clientSecret = "client-secret";
    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/login/self-oauth2-basic1111")
    public String login() {
        // GitHub OAuth 授权 URL
        String url = "http://localhost:8080/oauth/authorize" +
                "?response_type=code" +
                "&client_id=" + clientId +
                "&scope=read write" +
                "&redirect_uri=http://localhost:8083/self-oauth2/callbackBasic1111";
        String username="admin";
        String password="admin";
        String userAuth = username + ":" + password;
        String encodedUserAuth = Base64.getEncoder().encodeToString(userAuth.getBytes());

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Basic " + encodedUserAuth);

        // 不自动重定向
        HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory();
        HttpClient httpClient = HttpClientBuilder.create()
                .disableRedirectHandling()
                .build();
        factory.setHttpClient(httpClient);
        restTemplate.setRequestFactory(factory);

        ResponseEntity<String> response = restTemplate.exchange(
                url,
                HttpMethod.GET,
                new HttpEntity<>(headers),
                String.class
        );

        // 从重定向URL中提取授权码
        String code="";
        String location = response.getHeaders().getFirst("Location");
        if (location != null && location.contains("code=")) {
            code=location.split("code=")[1].split("&")[0];
        }

        //restTemplate没有配置[不自动重定向]时，可以这么做
        //String code = response.getBody();

        headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("client_id", clientId);
        params.add("client_secret", clientSecret);
        params.add("grant_type", "authorization_code");//必须要
        params.add("code", code);
        params.add("redirect_uri", "http://localhost:8083/self-oauth2/callbackBasic1111");//必须要

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        Map<String, Object> resp = restTemplate.postForObject(
                "http://localhost:8080/oauth/token",
                request,
                Map.class
        );

        String accessToken = (String) resp.get("access_token");

        return accessToken;

    }

    //restTemplate没有配置[不自动重定向]时，可以这么做
//    @GetMapping("/self-oauth2/callbackBasic1111")
//    public String callback(@RequestParam String code, HttpServletResponse response) {
//        return code;
//    }

}
