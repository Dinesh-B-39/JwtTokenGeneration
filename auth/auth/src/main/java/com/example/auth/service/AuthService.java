package com.example.auth.service;

import com.example.auth.dto.*;
import com.example.auth.model.User;
import com.example.auth.repository.UserRepository;
import com.example.auth.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    @Autowired
    UserRepository userRepository;

    @Autowired
    BCryptPasswordEncoder encoder;

    @Autowired
    JwtUtil jwtUtil;

//    public AuthService(UserRepository userRepository,
//                       BCryptPasswordEncoder encoder,
//                       JwtUtil jwtUtil) {
//        this.userRepository = userRepository;
//        this.encoder = encoder;
//        this.jwtUtil = jwtUtil;
//    }

    public void register(RegisterRequest request) {

        if (userRepository.existsByUsername(request.getUsername()))
            throw new RuntimeException("Username exists");

        User user = new User();
        user.setUsername(request.getUsername());
        user.setPassword(encoder.encode(request.getPassword()));
        user.setEmail(request.getEmail());
        user.setPhone(request.getPhone());
        user.setRole("ROLE_USER");

        userRepository.save(user);
    }

    public JwtResponse login(LoginRequest request) {

        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new RuntimeException("Invalid user"));

        if (!encoder.matches(request.getPassword(), user.getPassword()))
            throw new RuntimeException("Invalid password");

        String token = jwtUtil.generateToken(
                user.getUsername(), user.getRole());

        return new JwtResponse(token);
    }
}
