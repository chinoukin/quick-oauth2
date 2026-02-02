package com.quick.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final JwtFilter jwtFilter;

    public SecurityConfig(JwtFilter jwtFilter) {
        this.jwtFilter = jwtFilter;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable() // 演示环境可禁用 CSRF
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 无状态
                .and()
                .authorizeRequests()
                .antMatchers("/", "/login/**", "/self-oauth2/**", "/api/logout").permitAll() // 首页、登录、回调开放
                .anyRequest().authenticated() // 其他路径必须 JWT
                .and()
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        //用OAuth2内部集成的登录
//        http
//                .csrf().disable() // 演示环境可禁用 CSRF
//                .sessionManagement()
//                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 无状态
//                .and()
//                .authorizeRequests()
//                .antMatchers("/", "/login/**", "/self-oauth2/**", "/api/logout").permitAll() // 首页、登录、回调开放
//                .anyRequest().authenticated() // 其他路径必须 JWT
//                .and()
//                .oauth2Login()
//                .successHandler(successHandler())
//                .and()
//                .oauth2Client()
//                .and()
//                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
    }

//    @Bean
//    public OAuth2AuthorizedClientRepository authorizedClientRepository() {
//        return new HttpSessionOAuth2AuthorizedClientRepository();
//    }
//
//    @Bean
//    public AuthenticationSuccessHandler successHandler() {
//        return (request, response, authentication) -> {
//
//            OAuth2AuthenticationToken token =
//                    (OAuth2AuthenticationToken) authentication;
//
//            OAuth2AuthorizedClient client =
//                    authorizedClientRepository().loadAuthorizedClient(
//                            token.getAuthorizedClientRegistrationId(),
//                            token,
//                            request
//                    );
//
//            String jwt = client.getAccessToken().getTokenValue();
//
//            response.setContentType("application/json;charset=UTF-8");
//            response.getWriter().write("{\"token\":\"" + jwt + "\"}");
//        };
//    }
}