package ktb.week4.post;

import ktb.week4.comment.Comment;
import ktb.week4.comment.CommentRepository;
import ktb.week4.comment.CommentService;
import ktb.week4.image.Image;
import ktb.week4.post.postImage.PostImage;
import ktb.week4.post.postImage.PostImageRepository;
import ktb.week4.post.postImage.PostImageService;
import ktb.week4.post.postView.PostView;
import ktb.week4.post.postView.PostViewRepository;
import ktb.week4.post.postView.PostViewService;
import ktb.week4.user.User;
import ktb.week4.image.ImageRepository;
import ktb.week4.user.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static ktb.week4.post.PostDto.*;

@Service
@RequiredArgsConstructor
public class PostService {
    private final PostRepository postRepository;
    private final UserService userService;
    private final PostViewRepository postViewRepository;
    private final CommentService commentService;
    private final PostImageService postImageService;
    private final PostViewService postViewService;

    @Transactional(readOnly = true)
    public Page<PostOverviewResponse> getAllPosts(Pageable pageable) {
        Page<Post> postPage = postRepository.findAll(pageable);
        List<Long> postIds = postPage.getContent().stream()
                .map(Post::getId)
                .toList();

        List<PostView> postViews = postViewRepository.findAllById(postIds);

        Map<Long, PostView> postViewMap = postViews.stream()
                .collect(Collectors.toMap(pv -> pv.getPost().getId(), pv -> pv));

        List<PostOverviewResponse> responseList = postPage.getContent().stream()
                .map(post -> {
                    PostView postView = postViewMap.get(post.getId());
                    return PostOverviewResponse.of(post, postView);
                })
                .toList();


        return new PageImpl<>(responseList, pageable, postPage.getTotalElements());

    }

    @Transactional(readOnly = true)
    public PostDetailResponse getPost(Long postId) {
        Post post = getPostById(postId);
        PostView postView = postViewService.getPostViewById(postId);

        List<PostImage> postImages = postImageService.getPostImagesByPostId(postId);
        List<PostImageResponse> postImagesResponses = new ArrayList<>();
        for (PostImage postImage : postImages) {
            PostImageResponse response = PostImageResponse.of(postImage);
            postImagesResponses.add(response);
        }

        List<Comment> comments = commentService.getCommentsByPostId(postId);
        List<CommentResponse> commentResponses = new ArrayList<>();
        for (Comment comment : comments) {
            CommentResponse respone = CommentResponse.of(comment);
            commentResponses.add(respone);
        }

        return PostDetailResponse.of(post, postView, postImagesResponses, commentResponses);
    }

    @Transactional
    public Long createPost(String title, String content, User user) {
        Post post = Post.builder()
                .user(user)
                .postTitle(title)
                .postContent(content)
                .build();
        postRepository.save(post);

        PostView postView = PostView.builder()
                .post(post)
                .build();
        postViewRepository.save(postView);

        return post.getId();

    }

    @Transactional
    public Long updatePost(Long postId, String title, String content, User user) {
        validateUser(postId, user);

        Post post = getPostById(postId);

        if (title != null) {
            post.updatePostTitle(title);
        }

        if (content != null) {
            post.updatePostContent(content);
        }

        postRepository.save(post);

        return post.getId();
    }

    @Transactional
    public void deletePost(Long postId, User user) {
        validateUser(postId, user);

        Post post = getPostById(postId);
        postRepository.delete(post); // cascade
    }

    public Post getPostById(Long postId) {
        return postRepository.findById(postId)
                .orElseThrow(() -> new IllegalArgumentException("Post id " + postId + " not found"));
    }

    private void validateUser(Long postId, User user) {
        Post post = getPostById(postId);

        if (!post.getUser().getId().equals(user.getId())) {
            throw new IllegalArgumentException("forbidden user");
        }
    }

}
