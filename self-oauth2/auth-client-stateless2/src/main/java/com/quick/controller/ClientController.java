package com.quick.controller;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import java.security.KeyPair;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.util.Collections;
import java.util.Date;
import java.util.Map;

@Controller
public class ClientController {

    private final String clientId = "client-app";
    private final String clientSecret = "client-secret";
    //private final String jwtSecret = "secret-key-12345";
    private final RestTemplate restTemplate = new RestTemplate();

    @Autowired
    private KeyPair keyPair;

    @GetMapping("/")
    public String index(@CookieValue(value = "token", required = false) String token, Model model) {
        if (token != null) {
            try {
                //Claims claims = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();
                // 使用与auth-server密钥对想对应的公钥即可
                Claims claims = Jwts.parser().setSigningKey(keyPair.getPublic()).parseClaimsJws(token).getBody();
                model.addAttribute("username", claims.get("user_name"));
            } catch (Exception e) {
                // token 过期或无效
            }
        }
        return "index";
    }

    @GetMapping("/login/self-oauth2")
    public String login() {
        // GitHub OAuth 授权 URL
        String url = "http://localhost:8080/oauth/authorize" +
                "?response_type=code" +
                "&client_id=" + clientId +
                "&scope=read write" +
                "&redirect_uri=http://localhost:8083/self-oauth2/callback";
        return "redirect:" + url;
    }

    @GetMapping("/self-oauth2/callback")
    public String callback(@RequestParam String code, HttpServletResponse response) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("client_id", clientId);
        params.add("client_secret", clientSecret);
        params.add("grant_type", "authorization_code");//必须要
        params.add("code", code);
        params.add("redirect_uri", "http://localhost:8083/self-oauth2/callback");//必须要

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        Map<String, Object> resp = restTemplate.postForObject(
                "http://localhost:8080/oauth/token",
                request,
                Map.class
        );

        String accessToken = (String) resp.get("access_token");

        // 2️⃣ access_token -> 用户信息
//        HttpHeaders userHeaders = new HttpHeaders();
//        userHeaders.setBearerAuth(accessToken);  // Authorization: Bearer <token>
//        HttpEntity<Void> userEntity = new HttpEntity<>(userHeaders);
//
//        ResponseEntity<Map> userResponse = restTemplate.exchange(
//                "http://localhost:8081/userinfo",
//                HttpMethod.GET,
//                userEntity,
//                Map.class
//        );
//
//        Map userInfo = userResponse.getBody();
//        String username = userInfo.get("user_name").toString();
//
//        OffsetDateTime now = OffsetDateTime.now(ZoneId.of("Asia/Shanghai"));
//        OffsetDateTime expTime = now.plusSeconds(10 * 60);//10分钟
        // 3️⃣ 生成 JWT(对称加密)
//        String jwt = Jwts.builder()
//                .setSubject(username)
//                .setClaims(userInfo)
//                .setIssuedAt(Date.from(now.toInstant()))
//                .setExpiration(Date.from(expTime.toInstant()))
//                .signWith(SignatureAlgorithm.HS256, jwtSecret)
//                .compact();

        // 3️⃣ 生成 JWT(如果希望生成与auth-server一样的jwt，能被resource-server信任的jwt)
//        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(
//                new ClassPathResource("keystore.jks"),
//                "123456".toCharArray()
//        );
//
//        KeyPair keyPair = keyStoreKeyFactory.getKeyPair("jwt-key");
//        String jwt = Jwts.builder()
//                .setSubject(username)
//                .setClaims(userInfo)
//                .setIssuedAt(Date.from(now.toInstant()))
//                .setExpiration(Date.from(expTime.toInstant()))
//                .signWith(SignatureAlgorithm.RS256, keyPair.getPrivate())
//                .compact();

        // 4️⃣ 写 cookie 返回浏览器
        //Cookie cookie = new Cookie("token", jwt);
        Cookie cookie = new Cookie("token", accessToken);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        response.addCookie(cookie);

        return "redirect:/";
    }

    @GetMapping("/api/logout")
    public String logout(HttpServletResponse response) {
        Cookie cookie = new Cookie("token", null);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
        return "redirect:/";
    }

    @GetMapping("/test")
    @PreAuthorize("hasRole('ADMIN')")
    public String test(@CookieValue(value = "token", required = false) String token, HttpServletRequest request, Model model) {
        if (token == null) {
            String header = request.getHeader("Authorization");
            if (header != null && header.startsWith("Bearer ")) {
                token = header.substring(7);
            }
        }
        if (token != null) {
            try {
                //Claims claims = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();
                // 使用与auth-server密钥对想对应的公钥即可
                Claims claims = Jwts.parser().setSigningKey(keyPair.getPublic()).parseClaimsJws(token).getBody();
                model.addAttribute("username", claims.get("user_name"));
                model.addAttribute("msg", "test success");
            } catch (Exception e) {
                // token 过期或无效
            }
        }
        return "index";
    }

    @GetMapping("/test2")
    //@PreAuthorize("hasRole('ADMIN')")
    //@PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @PreAuthorize("hasAnyAuthority('SCOPE_read','SCOPE_write')")
    public String test2(@CookieValue(value = "token", required = false) String token, HttpServletRequest request, Model model) {
        if (token == null) {
            String header = request.getHeader("Authorization");
            if (header != null && header.startsWith("Bearer ")) {
                token = header.substring(7);
            }
        }
        if (token != null) {
            try {
                //Claims claims = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();
                // 使用与auth-server密钥对想对应的公钥即可
                Claims claims = Jwts.parser().setSigningKey(keyPair.getPublic()).parseClaimsJws(token).getBody();
                model.addAttribute("username", claims.get("user_name"));
                model.addAttribute("msg", "test success");
            } catch (Exception e) {
                // token 过期或无效
            }
        }
        return "index";
    }
}
