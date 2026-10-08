package com.rishi.urlshortener.service;

import com.rishi.urlshortener.dto.AuthRequest;
import com.rishi.urlshortener.dto.AuthResponse;
import com.rishi.urlshortener.exception.ValidationException;
import com.rishi.urlshortener.model.User;
import com.rishi.urlshortener.repository.UserRepository;
import com.rishi.urlshortener.security.JwtProvider;
import com.rishi.urlshortener.util.PasswordUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordUtil passwordUtil;
    private final JwtProvider jwtProvider;

    /**
     * Register a new user.
     */
    @Transactional
    public AuthResponse register(AuthRequest request) {
        // Validate input
        if (request.getUsername() == null || request.getUsername().isEmpty()) {
            throw new ValidationException("Username is required");
        }
        if (request.getEmail() == null || request.getEmail().isEmpty()) {
            throw new ValidationException("Email is required");
        }
        if (request.getPassword() == null || request.getPassword().length() < 6) {
            throw new ValidationException("Password must be at least 6 characters");
        }

        // Check if user already exists
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new ValidationException("Username already taken: " + request.getUsername());
        }
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new ValidationException("Email already registered: " + request.getEmail());
        }

        // Encode password and create user
        String encodedPassword = passwordUtil.encodePassword(request.getPassword());
        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .passwordHash(encodedPassword)
                .fullName(request.getFullName())
                .isActive(true)
                .build();

        user = userRepository.save(user);

        // Generate JWT token
        String token = jwtProvider.generateToken(user.getId(), user.getUsername());

        log.info("User registered: {} ({})", user.getUsername(), user.getEmail());

        return AuthResponse.builder()
                .token(token)
                .type("Bearer")
                .userId(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .expiresIn("1 day")
                .build();
    }

    /**
     * Login an existing user.
     */
    public AuthResponse login(AuthRequest request) {
        // Validate input
        if (request.getUsername() == null || request.getUsername().isEmpty()) {
            throw new ValidationException("Username is required");
        }
        if (request.getPassword() == null || request.getPassword().isEmpty()) {
            throw new ValidationException("Password is required");
        }

        // Find user
        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new ValidationException("Invalid username or password"));

        // Check if user is active
        if (!user.getIsActive()) {
            throw new ValidationException("User account is inactive");
        }

        // Verify password
        if (!passwordUtil.matchesPassword(request.getPassword(), user.getPasswordHash())) {
            throw new ValidationException("Invalid username or password");
        }

        // Generate JWT token
        String token = jwtProvider.generateToken(user.getId(), user.getUsername());

        log.info("User logged in: {}", user.getUsername());

        return AuthResponse.builder()
                .token(token)
                .type("Bearer")
                .userId(user.getId())
                .username(user.getUsername())
                .email(user.getEmail())
                .expiresIn("1 day")
                .build();
    }
}
