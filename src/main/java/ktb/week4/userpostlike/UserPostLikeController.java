package ktb.week4.userpostlike;

import jakarta.servlet.http.HttpServletRequest;
import ktb.week4.user.User;
import ktb.week4.user.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/userlikes/{postId}")
@RequiredArgsConstructor
public class UserPostLikeController {
    private final UserPostLikeService userPostLikeService;
    private final UserService userService;

    @PostMapping
    public ResponseEntity<?> addLike(@PathVariable Long postId,
                                     HttpServletRequest servletRequest) {

        Long userId = (Long) servletRequest.getAttribute("userId");
        User user = userService.getUser(userId);
        userPostLikeService.addLike(postId, user);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping
    public ResponseEntity<?> removeLike(@PathVariable Long postId,
                                        HttpServletRequest servletRequest) {
        Long userId = (Long) servletRequest.getAttribute("userId");
        User user = userService.getUser(userId);
        userPostLikeService.removeLike(postId, user);
        return ResponseEntity.ok().build();
    }


}
