package ktb.week4.config;

import jakarta.servlet.Filter;
import ktb.week4.Login.JwtAuthFilter;
import ktb.week4.Login.SessionAuthFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class WebFilterConfig {

    private final JwtAuthFilter jwtAuthFilter;

    @Bean
    public FilterRegistrationBean<Filter> filterRegistrationBean() {
        FilterRegistrationBean<Filter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(jwtAuthFilter);
        registrationBean.addUrlPatterns("/*");
        registrationBean.setOrder(1);
        return registrationBean;

    }

}
