package com.javierrodriguez.springsecurityexample.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.apache.juli.logging.Log;
import org.slf4j.Logger;

import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final Logger Log = LoggerFactory.getLogger(this.getClass());

    private final AuthenticationManager authenticationManager;
    public JwtAuthenticationFilter(AuthenticationManager authenticationManager){
        this.authenticationManager= authenticationManager;
        setFilterProcessesUrl("/api/authenticate");
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response){
        String  username = request.getParameter("username");
        String password = request.getParameter("password");
       Log.warn(username + password);
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        return authenticationManager.authenticate(authenticationToken);
    }

    @Override
    public void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain,
                                         Authentication authentication){
        User user = (User) authentication.getPrincipal();
       List<String> roles = user.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());
            byte[] palaabraSecreta = "n2r5u8x/A%D*G-KaPdSgVkYp3s6v9y$B&E(H+MbQeThWmZq4t7w!z%C*F-J@NcRf".getBytes();
            Log.warn(palaabraSecreta.toString());
            String token = Jwts.builder()
                    .signWith(Keys.hmacShaKeyFor(palaabraSecreta), SignatureAlgorithm.HS512)
                    .setHeaderParam("type", "jwt")
                    .setIssuer("secure-api")
                    .setAudience("secuer-app")
                    .setSubject(user.getUsername())
                    .setExpiration(new Date(System.currentTimeMillis()+864000000))
                    .claim("rol", roles)
                    .compact();
                response.addHeader("Authorization","Bearer "+ token );

    }


}
