package com.playground.springSecurity.service;

import com.playground.springSecurity.entity.Users;
import com.playground.springSecurity.enums.AuthProvider;
import com.playground.springSecurity.enums.Role;
import com.playground.springSecurity.repository.UsersRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AppOauth2UserService extends OidcUserService {

    private final UsersRepository usersRepository;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {

        // get user detailed info from google
        OidcUser userFromGoogle = super.loadUser(userRequest);

        String email = userFromGoogle.getEmail();

        // check and fetch user from our local database if exist
        Users localUser = usersRepository.findByEmail(email).orElseGet(
                () -> {
                    // create custom username from Google info provided
                    String username = (
                            userFromGoogle
                                    .getGivenName()
                                    .charAt(0)+userFromGoogle
                                    .getFamilyName()
                    ).trim().toLowerCase();

                    // get user full name from Google
                    String fullName = userFromGoogle.getFullName().toLowerCase();

                    Users newLocalUser = new Users();
                    newLocalUser.setName(fullName);
                    newLocalUser.setEmail(email);
                    newLocalUser.setUsername(username);
                    newLocalUser.setPassword(null);
                    newLocalUser.setRole(Role.USER);
                    newLocalUser.setAuthProvider(AuthProvider.GOOGLE);
                    return usersRepository.save(newLocalUser);
                }
        );

        // get local roles
        Collection<? extends GrantedAuthority> authorities = localUser.getRole().getAuthorities();

        // DefaultOidcUser helps modify the userDetails that will be passed to spring security
        // so our system or app roles is added to what google provides
        return new DefaultOidcUser(
                authorities, userFromGoogle.getIdToken(), userFromGoogle.getUserInfo()
        );
    }
}
