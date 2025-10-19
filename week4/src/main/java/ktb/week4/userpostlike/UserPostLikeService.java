package ktb.week4.userpostlike;

import ktb.week4.post.Post;
import ktb.week4.post.PostService;
import ktb.week4.post.postView.PostViewService;
import ktb.week4.user.User;
import ktb.week4.user.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserPostLikeService {
    private final UserPostLikeRepository userPostLikeRepository;
    private final PostService postService;
    private final UserService userService;
    private final PostViewService postViewService;

    @Transactional
    public void createUserPostLike(Long postId, User user) {
        Post post = postService.getPostById(postId);
        validateOwner(user, post.getUser());

        UserPostLike userPostLike = UserPostLike.builder()
                .user(user)
                .post(post)
                .build();
        userPostLikeRepository.save(userPostLike);

        postViewService.updateLikeCount(postId, false);
    }

    @Transactional
    public void deleteUserPostLike(Long postId, User user) {
        Post post = postService.getPostById(postId);

        userPostLikeRepository.deleteByUserAndPost(user, post);
        postViewService.updateLikeCount(postId, true);
    }

    private void validateOwner(User user, User postUser) {
        if (user.getId().equals(postUser.getId())) {
            throw new IllegalArgumentException("post owner can't like own posts");
        }
    }
}
