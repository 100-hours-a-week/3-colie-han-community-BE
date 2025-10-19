package ktb.week4.post.postImage;

import ktb.week4.image.Image;
import ktb.week4.image.ImageService;
import ktb.week4.post.Post;
import ktb.week4.post.PostRepository;
import ktb.week4.post.PostService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@Service
@RequiredArgsConstructor
public class PostImageService {
    private final PostImageRepository postImageRepository;
    private final ImageService imageService;
    private final PostRepository postRepository;

    @Transactional
    public void createPostImages(Long postId, List<MultipartFile> postImages) {
        Post post = postRepository.findById(postId)
                .orElseThrow(()-> new IllegalArgumentException("Post not found"));

        int idx = 1;
        for (MultipartFile postImage : postImages) {
            Image image = imageService.uploadImage(postImage);

            PostImage postImagePostImage = PostImage.builder()
                    .post(post)
                    .image(image)
                    .sortOrder(idx)
                    .build();
            postImageRepository.save(postImagePostImage);
            idx++;
        }
    }

    public void updatePostImages(Long postId, List<MultipartFile> postImages) {
        List<PostImage> existImages = getPostImagesByPostId(postId);
        deletePostImages(existImages);

        createPostImages(postId, postImages);
    }

    public void deletePostImages(List<PostImage> existImages) {
        for (PostImage postImage : existImages) {
            Image image = postImage.getImage();
            imageService.updateIsDeleted(image);

            postImageRepository.delete(postImage);
        }
    }

    public List<PostImage> getPostImagesByPostId(Long postId) {
        return postImageRepository.findAllById_PostId(postId);
    }

}
