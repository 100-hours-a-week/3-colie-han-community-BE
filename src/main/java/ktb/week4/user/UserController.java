package ktb.week4.user;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
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
        User user = userService.getLoggedInUser(servletRequest);
        UserResponse response = userService.getUsers(user);
        return ResponseEntity.ok(response);
    }

    @PatchMapping("/profile-image")
    public ResponseEntity<?> updateProfileImage(@RequestParam("file") MultipartFile file,
                                                HttpServletRequest servletRequest) {
        User user = userService.getLoggedInUser(servletRequest);
        userService.updateProfileImage(file, user);
        return ResponseEntity.ok().build();
    }

    @PatchMapping("/nickname")
    public ResponseEntity<?> updateNickname(@Valid @RequestBody nickNameUpdateRequest request,
                                            HttpServletRequest servletRequest) {
        User user = userService.getLoggedInUser(servletRequest);
        userService.updateNickname(request, user);
        return ResponseEntity.ok().build();
    }


    @PatchMapping("/password")
    public ResponseEntity<?> updatePassword(@Valid @RequestBody passwordUpdateRequest request,
                                            HttpServletRequest servletRequest) {

        User user = userService.getLoggedInUser(servletRequest);
        userService.updatePassword(request, user);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping
    public ResponseEntity<?> deleteUser(HttpServletRequest servletRequest) {
        User user = userService.getLoggedInUser(servletRequest);
        userService.deleteUser(user);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/session/login")
    public String login(@RequestBody loginRequest loginRequest, HttpServletRequest request) {

        boolean success = userService.loginWithSession(loginRequest.email(), loginRequest.password(), request);
        if (!success) {
            throw new CustomException(ErrorCode.USER_LOGIN_REQUEST);
        }

        return "redirect:/index";
    }

    @PostMapping("/session/logout")
    public ResponseEntity<?> logout(HttpServletRequest request) {
        userService.logout(request);
        return ResponseEntity.ok().build();
    }



}
