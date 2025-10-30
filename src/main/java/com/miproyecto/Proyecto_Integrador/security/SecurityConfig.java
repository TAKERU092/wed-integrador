package com.miproyecto.Proyecto_Integrador.security;



import com.miproyecto.Proyecto_Integrador.repository.ClienteRepo;
import com.miproyecto.Proyecto_Integrador.service.JwtService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.*;

import java.util.List;
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    PasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    SecurityFilterChain filter(HttpSecurity http,
                               JwtService jwtService,
                               ClienteRepo clienteRepo) throws Exception {

        var jwtFilter = new JwtAuthFilter(jwtService, clienteRepo);

        http
            .csrf(cs -> cs.disable())
            .cors(cors -> {})
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(a -> a
  .requestMatchers("/", "/*.html").permitAll()
  .requestMatchers("/css/**","/favicon.ico","/js/**","/img/**","/fonts/**","/files/**").permitAll() // 👈 AÑADIDO

  .requestMatchers(HttpMethod.POST, "/api/auth/login", "/api/clientes/register").permitAll()
  .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
  .requestMatchers(HttpMethod.GET, "/api/debug/**").permitAll()

  .requestMatchers(HttpMethod.POST, "/api/pedidos/**", "/api/pagos").hasRole("USER")
  .requestMatchers(HttpMethod.GET , "/api/pedidos/**", "/api/pagos").hasRole("USER")
  .anyRequest().authenticated()
)

            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        var config = new CorsConfiguration();
        // Permite cualquier origen (más fácil para la etapa de desarrollo/demo en la nube)
        config.setAllowedOriginPatterns(List.of("*"));
        // O, de forma más segura, incluye tu dominio de Railway explícitamente si conoces el frontend:
        // config.setAllowedOriginPatterns(List.of("https://wed-integrador-production.up.railway.app", "http://localhost:8081"));
        config.setAllowedMethods(List.of("GET","POST","PUT","DELETE","OPTIONS"));
        config.setAllowedHeaders(List.of("Content-Type","Authorization"));
        config.setAllowCredentials(true);

        var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
