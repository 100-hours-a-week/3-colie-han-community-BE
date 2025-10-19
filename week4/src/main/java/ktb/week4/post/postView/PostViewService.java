package ktb.week4.post.postView;

import ktb.week4.post.Post;
import ktb.week4.post.PostRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class PostViewService {

    private final PostViewRepository postViewRepository;

    public PostView getPostViewById(Long postId) {
        return postViewRepository.findById(postId)
                .orElseThrow(()-> new IllegalArgumentException("Post view not found"));
    }

    @Transactional
    public void updateCommentCount(Long postId, boolean isDeleted) {
        PostView postView = getPostViewById(postId);
        if (isDeleted) {
            postView.downCommentCount();
        } else {
            postView.upCommentCount();
        }

        postViewRepository.save(postView);
    }

    @Transactional
    public void updateLikeCount(Long postId, boolean isDeleted) {
        PostView postView = getPostViewById(postId);

        if (isDeleted) {
            postView.downLikeCount();
        } else {
            postView.upLikeCount();
        }

        postViewRepository.save(postView);
    }

    @Transactional
    public void updateViewsCount(Long postId) {
        PostView postView = getPostViewById(postId);
        postView.updateViewCount();
        postViewRepository.save(postView);
    }
}
