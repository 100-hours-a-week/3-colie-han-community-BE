package ktb.week4.user;

import ktb.week4.image.Image;
import ktb.week4.image.ImageService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import static ktb.week4.user.UserDto.*;


@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final ImageService imageService;

    @Transactional
    public Long signUp(SignUpRequest request) {
        validateEmail(request.email());
        validatePassword(request.password(), request.confirmPassword());

        Image image = imageService.uploadImage(request.profileImage());
        User user = createUser(request, image);

        return user.getId();
    }

    @Transactional
    public UserResponse getUsers(User user) {
        return UserResponse.from(user);
    }

    @Transactional
    public void updateProfileImage(MultipartFile file, User user) {
        Image existImage = user.getProfileImg();
        imageService.updateIsDeleted(existImage);

        Image image = imageService.uploadImage(file);
        user.updateProfileImage(image);

        userRepository.save(user);
    }

    @Transactional
    public void updateNickname(nickNameUpdateRequest request, User user) {
        validateNickname(request.nickName());

        user.updateNickName(request.nickName());
        userRepository.save(user);

        log.info("nickname updated");
    }

    @Transactional
    public void updatePassword(passwordUpdateRequest request, User user) {
        validatePassword(request.password(), request.confirmPassword());

        user.updatePassword(passwordEncoder.encode(request.password()));
        userRepository.save(user);

        log.info("password updated");
    }

    @Transactional
    public void deleteUser(User user) {
        user.updateIsDeleted();
    }


    private void validateEmail(String email) {
        if (userRepository.existsByEmail(email)) {
            throw new IllegalArgumentException("email is exist");
        }
    }

    private void validateNickname(String nickname) {
        if (userRepository.existsByNickName(nickname)) {
            throw new IllegalArgumentException("nickname is exist");
        }
    }

    private void validatePassword(String password, String confirmPassword) {
        if (!password.equals(confirmPassword)) {
            throw new IllegalArgumentException("passwords do not match");
        }
    }

    private User createUser(SignUpRequest request, Image image) {
        User user = User.builder()
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .nickName(request.nickName())
                .profileImg(image)
                .role("USER")
                .build();
        userRepository.save(user);
        return user;
    }


}
