package com.playground.springSecurity.controller;


import com.playground.springSecurity.dto.RequestUserInfo;
import com.playground.springSecurity.dto.RequestUserRegistrationInfo;
import com.playground.springSecurity.service.UsersService;
import jakarta.websocket.OnError;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class UserController {

    private final UsersService usersService;

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/users")
    public ResponseEntity<?> fetchUsers() {
        return usersService.fetchAllUsers();
    }

    @PostMapping("/users")
    public ResponseEntity<String> addUsers(@RequestBody RequestUserInfo userInfo) {
        return usersService.addUser(userInfo);
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@RequestBody RequestUserRegistrationInfo info) {
        return usersService.registerUser(info);
    }

    @GetMapping("/test")
    public ResponseEntity<String> test() {
        return ResponseEntity.ok("Test endpoint");
    }

}
