package com.quick.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Component
public class JwtFilter extends OncePerRequestFilter {

    //private final String jwtSecret = "secret-key-12345";

    @Autowired
    private KeyPair keyPair;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String token = "";
        Cookie cookie = getCookie(request, "token");
        if (cookie != null) {
            token = cookie.getValue();
        }
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            token = header.substring(7);
        }
        if (!"".equals(token)){
            try {
                Claims claims = Jwts.parser().setSigningKey(keyPair.getPublic()).parseClaimsJws(token).getBody();
                //String username = claims.getSubject();
                String username = (String) claims.get("user_name");
                List<GrantedAuthority> authorities = extractAuthorities(claims);

                UsernamePasswordAuthenticationToken auth =
                        new UsernamePasswordAuthenticationToken(
                                username,
                                null,
                                //Collections.emptyList()
                                authorities
                        );
                SecurityContextHolder.getContext().setAuthentication(auth);
            } catch (Exception e) {
                // token 过期或无效
            }
        }

        filterChain.doFilter(request, response);
    }

    private Cookie getCookie(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (name.equals(cookie.getName())) {
                    return cookie;
                }
            }
        }
        return null;
    }

    /**
     * 从JWT claims中提取权限信息
     */
    private List<GrantedAuthority> extractAuthorities(Claims claims) {
        List<GrantedAuthority> authorities = new ArrayList<>();

        // 方式1：从 "roles" 或 "authorities" 声明中提取
        if (claims.containsKey("roles")) {
            Object rolesObj = claims.get("roles");
            if (rolesObj instanceof List) {
                for (Object role : (List<?>) rolesObj) {
                    String roleName = role.toString();
                    // 确保有 ROLE_ 前缀
                    if (!roleName.startsWith("ROLE_")) {
                        roleName = "ROLE_" + roleName;
                    }
                    authorities.add(new SimpleGrantedAuthority(roleName));
                }
            }
        }

        // 方式2：从 "authorities" 声明中提取
        if (claims.containsKey("authorities")) {
            Object authsObj = claims.get("authorities");
            if (authsObj instanceof List) {
                for (Object auth : (List<?>) authsObj) {
                    authorities.add(new SimpleGrantedAuthority(auth.toString()));
                }
            }
        }

        // 方式3：从 "scope" 声明中提取
        if (claims.containsKey("scope")) {
            String scope = claims.get("scope", String.class);
            if (scope != null) {
                String[] scopes = scope.split(" ");
                for (String s : scopes) {
                    authorities.add(new SimpleGrantedAuthority("SCOPE_" + s));
                }
            }
        }

        // 如果没有找到权限信息，添加默认权限
        if (authorities.isEmpty()) {
            authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        }

        return authorities;
    }
}
