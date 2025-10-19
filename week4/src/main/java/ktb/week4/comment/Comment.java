package ktb.week4.comment;

import jakarta.persistence.*;
import ktb.week4.util.BaseEntity;
import ktb.week4.post.Post;
import ktb.week4.user.User;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "comments")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Comment extends BaseEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(columnDefinition = "BIGINT UNSIGNED")
    private Long id;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;

    @ManyToOne
    @JoinColumn(name = "post_id")
    private Post post;

    private String commentContent;

    @Builder
    private Comment(User user, Post post, String content) {
        this.user = user;
        this.post = post;
        this.commentContent = content;
    }

    protected void updateContent(String newContent) {
        if (newContent == null || newContent.isBlank()) {
            throw new IllegalArgumentException("댓글 내용은 비어있을 수 없습니다.");
        }
        this.commentContent = newContent;
    }
}
