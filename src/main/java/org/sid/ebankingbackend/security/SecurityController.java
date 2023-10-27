package org.sid.ebankingbackend.security;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/auth")
public class SecurityController {

    private AuthenticationManager authenticationManager;

    public SecurityController(AuthenticationManager authenticationManager){
        this.authenticationManager = authenticationManager;
    }

    @GetMapping("/profile")
    public Authentication authentication(Authentication authentication) {
        return authentication;
    }

    /*@PostMapping("/login")
    public Map<String, String> login(String username, String password){
       Authentication authentication = authenticationManager.authenticate(
               new UsernamePasswordAuthenticationToken(username, password)
       );
        Instant instant = Instant.now();
        String scope = authentication.getAuthorities()
                .stream().map(GrantedAuthority::getAuthority *//*a -> a.getAuthority()*//*)
                .collect(Collectors.joining(" "));

        JwtClaimsSet jwtClaimsSet = JwtClaimsSet.builder()
                .issuedAt(instant)
                .expiresAt(instant.plus(10, ChronoUnit.MINUTES))
                .subject(username)
                .claim("scope", scope)
                .build();
    }*/
}
