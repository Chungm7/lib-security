package com.pzyko_solutions.config;

import com.pzyko_solutions.jwt.JwtAuthenticationFilter;
import com.pzyko_solutions.jwt.JwtUtil;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

public class CommonSecurityAutoConfig {
    // 1. Define JwtUtil como un Bean
    @Bean
    @ConditionalOnMissingBean // Permite que la app lo sobreescriba si quiere
    public JwtUtil jwtUtil() {
        // Aquí puedes configurar JwtUtil si necesita un 'secret'
        // que podrías leer de @Value("${mi.propiedad.jwt.secret}")
        return new JwtUtil();
    }

    // 2. Define tu filtro y le inyecta JwtUtil (¡por constructor!)
    @Bean
    @ConditionalOnMissingBean
    public JwtAuthenticationFilter jwtAuthenticationFilter(JwtUtil jwtUtil) {
        // Spring ve que este Bean necesita un JwtUtil,
        // mira arriba, lo encuentra, y lo inyecta aquí.
        return new JwtAuthenticationFilter(jwtUtil);
    }
}
