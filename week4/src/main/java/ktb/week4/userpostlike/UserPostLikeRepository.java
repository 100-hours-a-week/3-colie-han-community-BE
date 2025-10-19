package ktb.week4.userpostlike;

import ktb.week4.post.Post;
import ktb.week4.user.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserPostLikeRepository extends JpaRepository<UserPostLike, UserPostLikeId> {
    void deleteByUserAndPost(User user, Post post);
}
