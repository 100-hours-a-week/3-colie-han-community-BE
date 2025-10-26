package ktb.week4.post.postView;

import jakarta.persistence.*;
import ktb.week4.post.Post;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "post_views")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class PostView {
    @Id
    @Column(name = "post_id")
    private Long id;

    @MapsId
    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "post_id", columnDefinition = "BIGINT UNSIGNED")
    private Post post;

    @Column(nullable = false, columnDefinition = "INT DEFAULT 0")
    private Integer viewCount;

    @Column(nullable = false, columnDefinition = "INT DEFAULT 0")
    private Integer likeCount;

    @Column(nullable = false, columnDefinition = "INT DEFAULT 0")
    private Integer commentCount;

    @Builder
    private PostView(Post post) {
        this.post = post;
        this.viewCount = 0;
        this.likeCount = 0;
        this.commentCount = 0;
    }

    protected void updateViewCount() {
        this.viewCount = this.viewCount + 1;
    }

    protected void upLikeCount() {
        this.likeCount = this.likeCount + 1;
    }

    protected void downLikeCount() {
        this.likeCount = this.likeCount - 1;
    }

    protected void upCommentCount() {
        this.commentCount = this.commentCount + 1;
    }

    protected void downCommentCount() {
        this.commentCount = this.commentCount - 1;
    }

}
