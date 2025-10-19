package ktb.week4.post.postImage;

import jakarta.persistence.*;
import ktb.week4.util.BaseEntity;
import ktb.week4.image.Image;
import ktb.week4.post.Post;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "post_images")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
public class PostImage extends BaseEntity {
    @EmbeddedId
    private PostImageId id;

    @ManyToOne(fetch = FetchType.LAZY)
    @MapsId("imageId")
    private Image image;

    @ManyToOne(fetch = FetchType.LAZY)
    @MapsId("postId")
    private Post post;

    private Integer sortOrder;

    @Builder
    private PostImage(Image image, Post post, Integer sortOrder) {
        this.image = image;
        this.post = post;
        this.id = new PostImageId(post.getId(), image.getId());
        this.sortOrder = sortOrder;
    }
}
