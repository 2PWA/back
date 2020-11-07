package com.ppwa.security.service;

import com.ppwa.security.clients.CustomUser;
import com.ppwa.security.clients.UserFeignClient;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
public class CustomUserDetails implements UserDetailsService {

    private static final String USER_NOT_FOUND_MESSAGE = "Error in login, the username does not exist in the system";

    private final UserFeignClient userFeignClient;

    public CustomUserDetails(UserFeignClient userFeignClient) {
        this.userFeignClient = userFeignClient;
    }

    @Override
    public UserDetails loadUserByUsername(String username) {
        var user = this.getUser(username);

        List<GrantedAuthority> authorities = user.getRoles()
                                                 .stream()
                                                 .map(SimpleGrantedAuthority::new)
                                                 .collect(Collectors.toList());

        return new User(user.getUsername(), user.getPassword(), authorities);
    }

    private CustomUser getUser(String username) {
        return Optional.ofNullable(userFeignClient.findByUsername(username))
                       .orElseThrow(() -> new UsernameNotFoundException(USER_NOT_FOUND_MESSAGE));
    }
}

