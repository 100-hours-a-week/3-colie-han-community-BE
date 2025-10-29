package ktb.week4.user;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import ktb.week4.util.exception.CustomException;
import ktb.week4.util.exception.ErrorCode;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;
import java.util.Set;

import static ktb.week4.user.UserDto.*;

@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Long> signup(@Valid @ModelAttribute SignUpRequest request) {

        Long userId = userService.signUp(request);
        return ResponseEntity.ok(userId);
    }

    @GetMapping
    public ResponseEntity<UserResponse> getUser(HttpServletRequest servletRequest) {
        Long userId = (Long) servletRequest.getAttribute("userId");
        User user = userService.getUser(userId);
        UserResponse response = userService.getUsers(user);
        return ResponseEntity.ok(response);
    }

    @PatchMapping("/profile-image")
    public ResponseEntity<?> updateProfileImage(@RequestParam("file") MultipartFile file,
                                                HttpServletRequest servletRequest) {
        Long userId = (Long) servletRequest.getAttribute("userId");
        User user = userService.getUser(userId);
        userService.updateProfileImage(file, user);
        return ResponseEntity.ok().build();
    }

    @PatchMapping("/nickname")
    public ResponseEntity<?> updateNickname(@Valid @RequestBody nickNameUpdateRequest request,
                                            HttpServletRequest servletRequest) {
        Long userId = (Long) servletRequest.getAttribute("userId");
        User user = userService.getUser(userId);
        userService.updateNickname(request, user);
        return ResponseEntity.ok().build();
    }


    @PatchMapping("/password")
    public ResponseEntity<?> updatePassword(@Valid @RequestBody passwordUpdateRequest request,
                                            HttpServletRequest servletRequest) {

        Long userId = (Long) servletRequest.getAttribute("userId");
        User user = userService.getUser(userId);
        userService.updatePassword(request, user);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping
    public ResponseEntity<?> deleteUser(HttpServletRequest servletRequest) {
        Long userId = (Long) servletRequest.getAttribute("userId");
        User user = userService.getUser(userId);
        userService.deleteUser(user);
        return ResponseEntity.ok().build();
    }


    @PostMapping("/jwt/login")
    public String loginWithJwt(@RequestBody loginRequest loginRequest, HttpServletResponse response) {
        String accessToken = userService.loginWithJwt(loginRequest.email(), loginRequest.password(), response);
        if (accessToken == null) {
            throw new CustomException(ErrorCode.USER_LOGIN_REQUEST);
        }
        return "redirect:/index";
    }

    @PostMapping("/jwt/logout")
    public String logout(HttpServletResponse servletResponse) {
        userService.logoutUser(servletResponse);
        return "redirect:/login";
    }

    @PostMapping("/refresh")
    @ResponseBody
    public Map<String, String> refresh(@CookieValue(value = "refreshToken", required = false) String refreshToken,
                                       HttpServletResponse response) {

        if (refreshToken == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return Map.of("error", "Refresh token missing");
        }

        try {
            var tokenRes = userService.refreshTokens(refreshToken, response);

            if (tokenRes == null) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                return Map.of("error", "Refresh token invalid or expired");
            }

            return Map.of(
                    "accessToken", tokenRes.accessToken(),
                    "refreshToken", tokenRes.refreshToken()
            );
        } catch (ResponseStatusException exception) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return Map.of("error", "Refresh token invalid or expired");
        }
    }





}
