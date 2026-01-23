package com.github.oauth.controller;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.http.*;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.util.*;

@Controller
public class GithubController {

    private final String clientId = "Ov23lizUMUyQojwwW44a";
    private final String clientSecret = "e97b00d1de993579355d759f709212c37da94b18";
    private final String jwtSecret = "very-secret-key";
    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/")
    public String index(@CookieValue(value = "token", required = false) String token, Model model) {
        if (token != null) {
            try {
                Claims claims = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();
                model.addAttribute("username", claims.getSubject());
            } catch (Exception e) {
                // token 过期或无效
            }
        }
        return "index";
    }

    @GetMapping("/login/github")
    public String login() {
        // GitHub OAuth 授权 URL
        String url = "https://github.com/login/oauth/authorize" +
                "?client_id=" + clientId +
                "&scope=read:user,user:email" +
                "&redirect_uri=http://localhost:8080/github/callback";
        return "redirect:" + url;
    }

    // 应在OAuthApps中配置Authorization callback URL为"http://localhost:8080/github/callback"
    @GetMapping("/github/callback")
    public String callback(@RequestParam String code, HttpServletResponse response) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("client_id", clientId);
        params.add("client_secret", clientSecret);
        params.add("code", code);

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(params, headers);

        Map<String, Object> resp = restTemplate.postForObject(
                "https://github.com/login/oauth/access_token",
                request,
                Map.class
        );

        String accessToken = (String) resp.get("access_token");

        // 2️⃣ access_token -> 用户信息
        HttpHeaders userHeaders = new HttpHeaders();
        userHeaders.setBearerAuth(accessToken);  // Authorization: Bearer <token>
        HttpEntity<Void> userEntity = new HttpEntity<>(userHeaders);

        ResponseEntity<Map> userResponse = restTemplate.exchange(
                "https://api.github.com/user",
                HttpMethod.GET,
                userEntity,
                Map.class
        );

        Map userInfo = userResponse.getBody();
        String username = userInfo.get("login").toString();

        OffsetDateTime now = OffsetDateTime.now(ZoneId.of("Asia/Shanghai"));
        OffsetDateTime expTime = now.plusSeconds(10 * 60);//10分钟
        // 3️⃣ 生成 JWT
        String jwt = Jwts.builder()
                .setSubject(username)
                .setIssuedAt(Date.from(now.toInstant()))
                .setExpiration(Date.from(expTime.toInstant()))
                .signWith(SignatureAlgorithm.HS256, jwtSecret)
                .compact();

        // 4️⃣ 写 cookie 返回浏览器
        Cookie cookie = new Cookie("token", jwt);
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
}
