package com.security.shiftmanager.dto;

import com.security.shiftmanager.model.Role;
import com.security.shiftmanager.model.User;

public record LoginResponse(
        String token,
        Long id,
        String username,
        String email,
        Role role
) {
    public static LoginResponse of(String token, User user) {
        return new LoginResponse(token, user.getId(), user.getUsername(), user.getEmail(), user.getRole());
    }
}
