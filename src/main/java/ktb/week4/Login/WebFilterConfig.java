package ktb.week4.Login;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.RestController;

@Configuration
@RequiredArgsConstructor
public class WebFilterConfig {

    private final SessionAuthFilter sessionAuthFilter;

    @Bean
    public FilterRegistrationBean<SessionAuthFilter> filterRegistrationBean() {
        FilterRegistrationBean<SessionAuthFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(sessionAuthFilter);
        registrationBean.addUrlPatterns("/*");
        registrationBean.setOrder(1);

        return registrationBean;

    }

}
