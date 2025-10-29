package ktb.week4.comment;

import jakarta.servlet.http.HttpServletRequest;
import ktb.week4.user.User;
import ktb.week4.user.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

import static ktb.week4.comment.CommentDto.*;

@RestController
@RequiredArgsConstructor
public class CommentController {

    private final CommentService commentService;
    private final UserService userService;

    @PostMapping("/posts/{postId}/comments")
    public void createComment(@PathVariable Long postId,
                              @RequestBody CommentCreateRequest request,
                              HttpServletRequest servletRequest) {

        User user = userService.getLoggedInUser(servletRequest);
        commentService.uploadComment(postId, request, user);
    }

    @PatchMapping("/comments/{commentId}")
    public void updateComment(@PathVariable Long commentId,
                              @RequestBody CommentUpdateRequest request,
                              HttpServletRequest servletRequest) {

        User user = userService.getLoggedInUser(servletRequest);
        commentService.updateComment(commentId, request, user);
    }

    @DeleteMapping("/posts/{postId}/comments/{commentId}")
    public void deleteComment(@PathVariable Long postId,
                              @PathVariable Long commentId,
                              HttpServletRequest servletRequest) {

        User user = userService.getLoggedInUser(servletRequest);
        commentService.deleteComment(postId, commentId, user);
    }
}
