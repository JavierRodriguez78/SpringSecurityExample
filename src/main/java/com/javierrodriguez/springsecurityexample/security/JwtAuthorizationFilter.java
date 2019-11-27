package com.javierrodriguez.springsecurityexample.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {


private static Logger log = LoggerFactory.getLogger("JwtAuthorizationFilter:class");

public JwtAuthorizationFilter (AuthenticationManager authenticationManager){
    super(authenticationManager);
}

@Override
public void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                              FilterChain filterChain) throws ServletException, IOException {


    if (!existJWT(request, response)){
                filterChain.doFilter(request,response);
                return;
            }
            Claims claims = this.validateJWT(request);
            if(claims.get("rol")!=null){
                this.setUpSpringAuthentication(claims);
            }else{
                SecurityContextHolder.clearContext();
            }




}

private boolean existJWT(HttpServletRequest request, HttpServletResponse response){
    String authenticationHeader = request.getHeader("Authorization");
    if (authenticationHeader ==null || !authenticationHeader.startsWith("Bearer"))
        return false;
    return true;
}

    private Claims validateJWT(HttpServletRequest req){
        String jwToken = req.getHeader("Authorization").replace("Bearer", "");
    return Jwts.parser()
            .setSigningKey("n2r5u8x/A%D*G-KaPdSgVkYp3s6v9y$B&E(H+MbQeThWmZq4t7w!z%C*F-J@NcRf".getBytes())
            .parseClaimsJws(jwToken).getBody();
    }

    private void setUpSpringAuthentication(Claims claims){
        List<String> authorities = (List<String>)claims.get("rol");
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(claims.getSubject(), null
        , authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));

        SecurityContextHolder.getContext().setAuthentication(auth);
}

}
