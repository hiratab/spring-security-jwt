package com.hiratab.springsecurityjwt.controller;


import com.hiratab.springsecurityjwt.models.AuthenticationRequest;
import com.hiratab.springsecurityjwt.models.AuthenticationResponse;
import com.hiratab.springsecurityjwt.service.MyUserDetailService;
import com.hiratab.springsecurityjwt.utils.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthenticationResource {

    @Autowired
    private MyUserDetailService myUserDetailService;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest authenticationRequest) throws Exception {

        try {
            authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authenticationRequest.getUsername(), authenticationRequest.getPassword())
            );
        } catch (BadCredentialsException exception) {
            throw new Exception("Incorret username or password", exception);
        }

        final UserDetails userDetails = myUserDetailService.loadUserByUsername(authenticationRequest.getUsername());
        final String jwt = jwtUtils.generateToken(userDetails);

        return ResponseEntity.ok(new AuthenticationResponse(jwt));
    }
}
