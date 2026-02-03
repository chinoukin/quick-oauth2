package com.quick.controller;


import com.quick.user.User;
import com.quick.user.UserService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.security.KeyPair;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.util.*;

@Controller
public class LocalAuthController {

    private final UserService userService;
    //private final String jwtSecret = "secret-key-12345";
    @Autowired
    private KeyPair keyPair;

    public LocalAuthController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/login")
    public String login(
            @RequestParam String username,
            @RequestParam String password,
            HttpServletResponse response,
            Model model
    ) {
        User user = userService.authenticate(username, password);
        if (user == null) {
            //throw new RuntimeException("用户名或密码错误");
            model.addAttribute("msg", "用户名或密码错误");
            return "index";
        }


        // claims
        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("user_name", username);
        Collection<SimpleGrantedAuthority> collection = new ArrayList<>();
        //collection.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
        collection.add(new SimpleGrantedAuthority("ROLE_USER"));
        userInfo.put("authorities", collection);

        OffsetDateTime now = OffsetDateTime.now(ZoneId.of("Asia/Shanghai"));
        //OffsetDateTime expTime = now.plusSeconds(10*60);//10分钟
        OffsetDateTime expTime = now.plusSeconds(2 * 60);//2分钟
        // 3️⃣ 生成 JWT
        String jwt = Jwts.builder()
                .setSubject(username)
                .setClaims(userInfo)
                .setIssuedAt(Date.from(now.toInstant()))
                .setExpiration(Date.from(expTime.toInstant()))
                //.signWith(SignatureAlgorithm.HS256, jwtSecret)
                .signWith(SignatureAlgorithm.RS256, keyPair.getPrivate())
                .compact();

        Cookie cookie = new Cookie("token", jwt);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        response.addCookie(cookie);

        return "redirect:/";
    }
}
