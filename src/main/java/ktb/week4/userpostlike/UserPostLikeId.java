package ktb.week4.userpostlike;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.Objects;

@Embeddable
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class UserPostLikeId implements Serializable {

    @Column(name = "user_id")
    private Long userId;

    @Column(name = "post_id")
    private Long postId;

    protected UserPostLikeId(Long userId, Long postId) {
        this.userId = userId;
        this.postId = postId;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (!(obj instanceof UserPostLikeId)) return false;
        UserPostLikeId userPostLikeId = (UserPostLikeId) obj;
        return Objects.equals(userId, userPostLikeId.userId) &&
                Objects.equals(postId, userPostLikeId.postId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(userId, postId);
    }





}
