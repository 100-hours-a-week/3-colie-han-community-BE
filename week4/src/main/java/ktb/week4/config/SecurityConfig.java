package ktb.week4.config;

import jakarta.servlet.http.HttpServletRequest;
import ktb.week4.Login.CookieUtil;
import ktb.week4.Login.JwtFilter;
import ktb.week4.Login.JwtUtil;
import ktb.week4.Login.LoginFilter;
import ktb.week4.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Collections;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final AuthenticationConfiguration authenticationConfiguration;
    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final CookieUtil cookieUtil;


    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(Collections.singletonList("http://localhost:63342"));
        configuration.setAllowedMethods(Collections.singletonList("*"));
        configuration.setAllowCredentials(true);
        configuration.setAllowedHeaders(Collections.singletonList("*"));
        configuration.setExposedHeaders(Collections.singletonList("Authorization"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                .csrf(AbstractHttpConfigurer::disable)

                .formLogin(AbstractHttpConfigurer::disable)

                .httpBasic(AbstractHttpConfigurer::disable)

                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/login", "/", "/signup", "/users/**", "/files/**").permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated())

                .addFilterBefore(new JwtFilter(jwtUtil, userRepository, cookieUtil), LoginFilter.class)
                .addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil, cookieUtil), UsernamePasswordAuthenticationFilter.class)

                .sessionManagement((session)-> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));



        return http.build();
    }
}
