package ktb.week4.userpostlike;

import jakarta.persistence.*;
import ktb.week4.post.Post;
import ktb.week4.user.User;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "users_posts_likes")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class UserPostLike {

    @EmbeddedId
    private UserPostLikeId id;

    @ManyToOne(fetch = FetchType.LAZY)
    @MapsId("userId")
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @MapsId("postId")
    private Post post;


    @Builder
    private UserPostLike(User user, Post post) {
        this.user = user;
        this.post = post;
        this.id = new UserPostLikeId(user.getId(), post.getId());
    }
}
