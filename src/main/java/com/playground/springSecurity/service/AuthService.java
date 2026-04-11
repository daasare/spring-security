package com.playground.springSecurity.service;

import com.playground.springSecurity.security.JWTUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authManager;
    private final JWTUtils jwtUtils;

    public String login(String username, String password) {
        authManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );
        return jwtUtils.generateToken(username);
    }
}
