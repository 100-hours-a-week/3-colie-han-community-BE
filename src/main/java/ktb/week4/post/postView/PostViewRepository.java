package ktb.week4.post.postView;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface PostViewRepository extends JpaRepository<PostView, Long> {
    List<PostView> findAllById(Iterable<Long> ids);
}
