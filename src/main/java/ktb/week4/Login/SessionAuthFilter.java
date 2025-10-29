package ktb.week4.Login;

import io.jsonwebtoken.Claims;
import jakarta.servlet.*;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


@Component
@RequiredArgsConstructor
@Order(Ordered.HIGHEST_PRECEDENCE)
public class SessionAuthFilter extends OncePerRequestFilter {


    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {

        String path = request.getRequestURI();
        String method = request.getMethod();

        // 회원가입(POST /users)은 제외
        if (path.equals("/users") && method.equalsIgnoreCase("POST")) {
            return true;
        }

        // 로그인, 에러 등 제외
        if (path.startsWith("/session/login") || path.startsWith("/error")) {
            return true;
        }
        // 나머지는 필터 적용
        return false;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        boolean isIndex = isIndexRequest(request);
        HttpSession session = request.getSession(false);

        if (session == null || session.getAttribute("userId")  == null) {

            if (isIndex) {
                response.sendRedirect("/login");
                return;
            }

            filterChain.doFilter(request, response);
            return;
        }

        if (!validateSession(request)) {
            response.sendRedirect("/login");
        }

        filterChain.doFilter(request, response);
    }


    private boolean isIndexRequest(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return "/".equals(uri) || "/index".equals(uri);
    }

    private boolean validateSession(HttpServletRequest request) {
        try {
            HttpSession session = request.getSession(false);
            if (session == null) {
                return false;
            }

            Object userId = session.getAttribute("userId");
            Object role = session.getAttribute("role");

            if (userId == null || role == null) {
                return false;
            }

            request.setAttribute("userId", userId);
            request.setAttribute("role", role);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

}
