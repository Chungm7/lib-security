package com.pzyko_solutions.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Component
public class JwtUtil {
    @Value("${jwt.secret}")
    private String secret;

    @Value("${jwt.expiration}")
    private int expiration;
    public String generateToken(Authentication authentication){
        UserDetails mainUser = (UserDetails) authentication.getPrincipal();
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes());
        return Jwts.builder()
                .setSubject(mainUser.getUsername())
                .claim("authorities", mainUser.getAuthorities())
                .setIssuedAt(new Date())
                .setExpiration(new Date(new Date().getTime() + expiration * 1000L))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public Boolean validateToken(String token, UserDetails userDetails, Instant lastPasswordChange) {
        final String userName = extractUserName(token);
        if (!userName.equals(userDetails.getUsername()) || isTokenExpired(token)) {
            return false;
        }
        // Extraemos la fecha de emisión (Issued At) del token
        final Date issuedAt = extractIssuedAt(token);
        // Si el usuario cambió su contraseña (lastPasswordChange no es null)
        // Y el token fue emitido ANTES de ese cambio...
        /*
        if (lastPasswordChange != null && issuedAt.toInstant().isBefore(lastPasswordChange)) {
            // El token es inválido.
            return false;
        }
        // ----> FIN DE LA NUEVA LÓGICA

        return true;
         */
        // El token es inválido.
        return lastPasswordChange == null || !issuedAt.toInstant().isBefore(lastPasswordChange);
        // ----> FIN DE LA NUEVA LÓGICA
    }

    public Date extractIssuedAt(String token) {
        return extractAllClaims(token).getIssuedAt();
    }


    public Boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }
    public Date extractExpiration(String token){
        return extractAllClaims(token).getExpiration();
    }
    public Claims extractAllClaims(String token){
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
    public String extractUserName(String token){
        return extractAllClaims(token).getSubject();
    }

    public List<GrantedAuthority> extractAuthorities(String token) {
        Claims claims = extractAllClaims(token);

        @SuppressWarnings("unchecked")
        List<Map<String, String>> authoritiesList = (List<Map<String, String>>) claims.get("authorities");

        if (authoritiesList != null) {
            return authoritiesList.stream()
                    .map(authMap -> new SimpleGrantedAuthority(authMap.get("authority")))
                    .collect(Collectors.toList());
        }

        return List.of();
    }
    // Método para validar sin necesidad de UserDetails
    public boolean validateToken(String token) {
        try {
            return !isTokenExpired(token);
        } catch (Exception e) {
            return false;
        }
    }

    // Extraer UUID del token
    public UUID extractUserId(String token) {
        return UUID.fromString(extractUserName(token));
    }
}
