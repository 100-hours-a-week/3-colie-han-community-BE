package ktb.week4.userpostlike;

import ktb.week4.post.Post;
import ktb.week4.post.PostRepository;
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
    private final PostViewService postViewService;
    private final PostRepository postRepository;

    @Transactional
    public void addLike(Long postId, User user) {
        Post post = getPostById(postId);

        validateOwner(user, post.getUser());

        createUserPostLike(user, post);
        postViewService.updateLikeCount(postId, false);
    }


    @Transactional
    public void removeLike(Long postId, User user) {
        Post post = getPostById(postId);

        validateOwner(user, post.getUser());

        userPostLikeRepository.deleteByUserAndPost(user, post);
        postViewService.updateLikeCount(postId, true);
    }

    private void validateOwner(User user, User postUser) {
        if (user.getId().equals(postUser.getId())) {
            throw new IllegalArgumentException("post owner can't like own posts");
        }
    }

    private void createUserPostLike(User user, Post post) {
        UserPostLike userPostLike = UserPostLike.builder()
                .user(user)
                .post(post)
                .build();
        userPostLikeRepository.save(userPostLike);
    }

    private Post getPostById(Long postId) {
        return postRepository.findById(postId)
                .orElseThrow(()-> new IllegalArgumentException("post not found"));
    }
}
