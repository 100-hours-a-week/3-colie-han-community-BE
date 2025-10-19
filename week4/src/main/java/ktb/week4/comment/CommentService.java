package ktb.week4.comment;


import ktb.week4.post.Post;
import ktb.week4.post.PostRepository;
import ktb.week4.post.postImage.PostImageService;
import ktb.week4.post.postView.PostViewService;
import ktb.week4.user.User;
import ktb.week4.post.PostService;
import ktb.week4.user.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static ktb.week4.comment.CommentDto.*;

@Service
@RequiredArgsConstructor
public class CommentService {
    private final CommentRepository commentRepository;
    private final PostRepository postRepository;

    @Transactional
    public void createComment(Long postId, CommentCreateRequest request, User user) {
        Post post = postRepository.findById(postId)
                .orElseThrow(()-> new IllegalArgumentException("Post not found"));

        Comment comment = Comment.builder()
                .post(post)
                .user(user)
                .content(request.content())
                .build();

        commentRepository.save(comment);
    }

    @Transactional
    public void updateComment(Long commentId, CommentUpdateRequest request, User user) {
        validateUser(commentId, user);

        Comment comment = getCommentById(commentId);
        comment.updateContent(request.content());
    }

    @Transactional
    public void deleteComment(Long commentId, User user) {
        validateUser(commentId, user);

        Comment comment = getCommentById(commentId);
        commentRepository.delete(comment);

    }

    public Comment getCommentById(Long commentId) {
        return commentRepository.findById(commentId)
                .orElseThrow(()-> new IllegalArgumentException("comment not found"));
    }

    public List<Comment> getCommentsByPostId(Long postId) {
        return commentRepository.findAllByPost_Id(postId);
    }

    private void validateUser(Long commentId, User user) {
        Comment comment = getCommentById(commentId);

        if (!comment.getUser().getId().equals(user.getId())) {
            throw new IllegalArgumentException("not allowed to update comment");
        }
    }
}
