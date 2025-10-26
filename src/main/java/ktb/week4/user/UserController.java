package ktb.week4.user;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

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
    public ResponseEntity<UserResponse> getUser(@CurrentUser User user) {
        UserResponse response = userService.getUsers(user);
        return ResponseEntity.ok(response);
    }

    @PatchMapping("/profile-image")
    public ResponseEntity<?> updateProfileImage(@RequestParam("file") MultipartFile file,
                                                @CurrentUser User user) {
        userService.updateProfileImage(file, user);
        return ResponseEntity.ok().build();
    }

    @PatchMapping("/nickname")
    public ResponseEntity<?> updateNickname(@Valid @RequestBody nickNameUpdateRequest request,
                                            @CurrentUser User user) {
        userService.updateNickname(request, user);
        return ResponseEntity.ok().build();
    }


    @PatchMapping("/password")
    public ResponseEntity<?> updatePassword(@Valid @RequestBody passwordUpdateRequest request,
                                            @CurrentUser User user) {

        userService.updatePassword(request, user);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping
    public ResponseEntity<?> deleteUser(@CurrentUser User user) {
        userService.deleteUser(user);
        return ResponseEntity.ok().build();
    }

}
