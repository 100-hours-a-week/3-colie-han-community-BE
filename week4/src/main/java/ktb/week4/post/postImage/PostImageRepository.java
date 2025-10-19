package ktb.week4.post.postImage;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface PostImageRepository extends JpaRepository<PostImage, PostImageId> {
    List<PostImage> findAllById_PostId(Long postId);
}
