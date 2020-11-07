package com.ppwa.security.clients;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class CustomUser {

    private static final String ROLE_USER = "user";
    private static final String ROLE_ADMIN = "admin";

    private String username;
    private String password;
    private boolean admin;

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public boolean isAdmin() {
        return admin;
    }

    public List<String> getRoles() {
        var roles = new ArrayList<>(Collections.singletonList(ROLE_USER));
        if (isAdmin()) {
            roles.add(ROLE_ADMIN);
        }
        return roles;
    }
}
