package ktb.week4.post;


import jakarta.validation.Valid;
import ktb.week4.user.CurrentUser;
import ktb.week4.post.postImage.PostImageService;
import ktb.week4.post.postView.PostViewService;
import ktb.week4.user.User;
import ktb.week4.user.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import static ktb.week4.post.PostDto.*;

@RequestMapping("/posts")
@RestController
@RequiredArgsConstructor
public class PostController {

    private final PostService postService;
    private final PostImageService postImageService;
    private final UserService userService;
    private final PostViewService postViewService;

    @GetMapping
    public ResponseEntity<Page<PostOverviewResponse>> getAllPosts(@PageableDefault(size = 10, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable) {
        Page<PostOverviewResponse> responsePage = postService.getAllPosts(pageable);
        return ResponseEntity.ok(responsePage);
    }

    @GetMapping("/{postId}")
    public ResponseEntity<PostDetailResponse> getPost(@PathVariable Long postId) {

        postViewService.updateViewsCount(postId);
        PostDetailResponse response = postService.getPost(postId);
        return ResponseEntity.ok(response);
    }

    @PostMapping
    public ResponseEntity<Long> createPost(@Valid @ModelAttribute PostRequest request,
                                           @CurrentUser User user) {

        // todo 게시물 생성 service 호출 -> 내부에서 post생성, image생성
        Long postId = postService.createPost(request.postTitle(), request.postContent(), user);
        if (request.files() != null) {

            postImageService.createPostImages(postId, request.files());
        }
        return ResponseEntity.ok(postId);
    }

    @PatchMapping("/{postId}")
    public ResponseEntity<?> updatePost(@PathVariable Long postId,
                                        @Valid @ModelAttribute PostRequest request,
                                        @CurrentUser User user) {

        Long response = postService.updatePost(postId, request.postTitle(), request.postContent(), user);
        if (request.files() != null &&  !request.files().isEmpty()) {
            postImageService.updatePostImages(postId, request.files());
        }

        return ResponseEntity.ok(response);
    }

    @DeleteMapping("/{postId}")
    public ResponseEntity<?> deletePost(@PathVariable Long postId,
                                        @CurrentUser User user) {

        postService.deletePost(postId, user);
        return ResponseEntity.ok().build();
    }
}

