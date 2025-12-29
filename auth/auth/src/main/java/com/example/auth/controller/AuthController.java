package com.example.auth.controller;

import com.example.auth.dto.*;
import com.example.auth.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    AuthService authService;


    @PostMapping("/register")
    public String register(@RequestBody RegisterRequest request) {
        authService.register(request);
        return "User Registered";
    }

    @PostMapping("/login")
    public JwtResponse login(@RequestBody LoginRequest request)
    {
        return authService.login(request);
    }
}
