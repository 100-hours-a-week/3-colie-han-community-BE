package ktb.week4.user;

import jakarta.persistence.*;
import ktb.week4.image.Image;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "users")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User {

    @Id @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(columnDefinition = "BIGINT UNSIGNED")
    private Long id;

    @Column(nullable = false)
    private String nickName;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    private String password;

    @OneToOne
    private Image profileImg;

    private String role;

    private Boolean isDeleted;

    @Builder
    public User(String nickName, String email, String password, Image profileImg, String role) {
        this.nickName = nickName;
        this.email = email;
        this.password = password;
        this.profileImg = profileImg;
        this.role = role;
        this.isDeleted = false;
    }

    protected void updateNickName(String nickName) {
        this.nickName = nickName;
    }

    protected void updatePassword(String password) {
        this.password = password;
    }

    protected void updateProfileImage(Image profileImg) {
        this.profileImg = profileImg;
    }

    protected void updateIsDeleted() {
        this.isDeleted = true;
    }
}
