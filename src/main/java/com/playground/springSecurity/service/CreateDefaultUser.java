package com.playground.springSecurity.service;

import com.playground.springSecurity.entity.Users;
import com.playground.springSecurity.enums.AuthProvider;
import com.playground.springSecurity.enums.Role;
import com.playground.springSecurity.repository.UsersRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CreateDefaultUser implements CommandLineRunner {

    private final UsersRepository usersRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * CommandLineRunner is a simple interface that lets
     * you run code automatically when the application starts.
     * **/

    @Override
    public void run(String... args) throws Exception {
        if (usersRepository.findByUsername("admin").isEmpty()) {
            Users defaultUser = new Users();
            defaultUser.setName("admin user");
            defaultUser.setUsername("admin");
            defaultUser.setEmail("admin@tallybucket.com");
            defaultUser.setRole(Role.ADMIN);
            defaultUser.setPassword(passwordEncoder.encode("GodAccount"));
            defaultUser.setAuthProvider(AuthProvider.LOCAL);
            usersRepository.save(defaultUser);
        }
    }
}
