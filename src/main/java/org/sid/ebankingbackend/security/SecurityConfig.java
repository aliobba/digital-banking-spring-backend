package org.sid.ebankingbackend.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

   @Bean
    public InMemoryUserDetailsManager inMemoryUserDetailsManager(){
       PasswordEncoder passwordEncoder= passwordEncoder();
       return new InMemoryUserDetailsManager(
               User.withUsername("user1").password(passwordEncoder.encode("12345")).authorities("USER").build(),
               User.withUsername("admin").password(passwordEncoder.encode("12345")).authorities("USER", "ADMIN").build()
       );
   }

   @Bean
    public PasswordEncoder passwordEncoder(){
       return new BCryptPasswordEncoder();
   }

   @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception{
       return httpSecurity
               .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
               .csrf(csrf -> csrf.disable())
               .authorizeHttpRequests(ar -> ar.anyRequest().authenticated())
               .httpBasic(Customizer.withDefaults())
//             .oauth2ResourceServer(/*OAuth2ResourceServerConfigurer::jwt*/ao -> ao.jwt(Customizer.withDefaults()))
               .build();
   }
}
