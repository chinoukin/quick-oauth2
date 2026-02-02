package com.github.oauth.user;


import org.springframework.stereotype.Service;

@Service
public class UserService {

    public User authenticate(String username, String password) {
        // 示例：实际应查数据库 + BCrypt
        if ("admin".equals(username) && "123456".equals(password)) {
            return new User(username);
        }
        return null;
    }
}
