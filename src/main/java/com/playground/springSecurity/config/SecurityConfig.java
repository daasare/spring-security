package com.playground.springSecurity.config;


import com.playground.springSecurity.filter.JWTAuthFilter;
import com.playground.springSecurity.service.AppOauth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity
@EnableMethodSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final JWTAuthFilter jwtAuthFilter;
    private final AppOauth2UserService appOauth2UserService;

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .oauth2Login(oauth2 -> oauth2.userInfoEndpoint(
                        userInfo -> userInfo.oidcUserService(appOauth2UserService)
                ))
                .authorizeHttpRequests(
                        auth -> auth
                                .requestMatchers(HttpMethod.GET, "/test").permitAll()
                                .requestMatchers(HttpMethod.GET, "/users").authenticated()
                                .anyRequest().authenticated()
                )
                /**
                 * By default, Spring Security expects a Username and Password
                 * (usually from a login form). Since we are using JWTs,
                 * you need to tell Spring: Before you try to look for a
                 * username/password form, check if there is a JWT in the
                 * header first.
                 * **/
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    /**
     * AuthenticationConfiguration pulls the manager out
     * of Spring's internal configuration.

     * When you call configuration.getAuthenticationManager(),
     * Spring Security performs an internal search (look-up) for
     * specific beans to build a ProviderManager. Here is the hierarchy
     * of how it finds them:
     *  1. Global Scan: Spring Security looks into the Application
     *     Context for any bean that implements UserDetailsService
     *     and any bean that implements PasswordEncoder.

     *  2. The DaoAuthenticationProvider: By default, Spring Security
     *      uses a provider called the DaoAuthenticationProvider.
     *      This provider is designed specifically to take a
     *      UserDetailsService and a PasswordEncoder and use them
     *      together to validate credentials.

     *  3. Automatic Linking: The AuthenticationConfiguration automatically
     *      takes those beans you defined elsewhere and injects them into
     *      that DaoAuthenticationProvider, which is then wrapped inside
     *      the AuthenticationManager you see in your code.
     * **/

    @Bean
    public AuthenticationManager manager(AuthenticationConfiguration configuration) {
        return configuration.getAuthenticationManager();
    }

}
