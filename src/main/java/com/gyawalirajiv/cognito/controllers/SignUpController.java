package com.gyawalirajiv.cognito.controllers;

import com.gyawalirajiv.cognito.model.User;
import com.gyawalirajiv.cognito.services.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

@RestController
@RequestMapping("/api")
public class SignUpController {

    @Autowired
    UserService userService;

    @PostMapping("/signup")
    public User signup(@RequestBody User user) throws InvalidKeyException, NoSuchAlgorithmException {
        return userService.signup(user);
    }

    @GetMapping("/users")
    public List<User> getAllUsers(){
        return userService.getAll();
    }

}
