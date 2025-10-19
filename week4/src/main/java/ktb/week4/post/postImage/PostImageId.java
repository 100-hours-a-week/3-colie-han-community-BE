package ktb.week4.post.postImage;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.Objects;

@Embeddable
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class PostImageId implements Serializable {

    @Column(name = "post_id")
    private Long postId;

    @Column(name = "image_id")
    private Long imageId;

    public PostImageId(Long postId, Long imageId) {
        this.postId = postId;
        this.imageId = imageId;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (! (obj instanceof PostImageId)) return false;
        PostImageId that = (PostImageId) obj;
        return Objects.equals(postId, that.postId) &&
                Objects.equals(imageId, that.imageId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(postId, imageId);
    }
}
