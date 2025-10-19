package ktb.week4.Login;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
public class CookieUtil {
    public ResponseCookie addCookie(String key, String value, long maxAge) {
        return ResponseCookie.from(key, value)
                .maxAge(maxAge)
                .path("/")
                .secure(false)
                .httpOnly(false)
                .sameSite("Lax")
                .build();
    }

    public ResponseCookie deleteCookie(String key) {
        return this.addCookie(key, "", 0);
    }

    public String findCookie(String key, Cookie[] cookies) {
        if (cookies == null) {
            return null;
        }
        for (Cookie cookie : cookies) {
            if (cookie.getName().equals(key)) {
                return cookie.getValue();
            }
        }
        return null;
    }
}
