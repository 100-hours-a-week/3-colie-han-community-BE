package ktb.week4.user;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import ktb.week4.image.Image;
import ktb.week4.image.ImageService;
import ktb.week4.util.exception.CustomException;
import ktb.week4.util.exception.ErrorCode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.util.Map;

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

        log.info("닉네임 변경 완료.");
    }

    @Transactional
    public void updatePassword(passwordUpdateRequest request, User user) {
        validatePassword(request.password(), request.confirmPassword());

        user.updatePassword(passwordEncoder.encode(request.password()));
        userRepository.save(user);

        log.info("비밀번호 변경 완료.");
    }

    @Transactional
    public void deleteUser(User user) {
        user.updateIsDeleted();
    }


    private void validateEmail(String email) {
        if (userRepository.existsByEmail(email)) {
            throw new CustomException(ErrorCode.EMAIL_ALREADY_EXISTS);
        }
    }

    private void validateNickname(String nickname) {
        if (userRepository.existsByNickName(nickname)) {
            throw new CustomException(ErrorCode.NICKNAME_ALREADY_EXISTS);
        }
    }

    private void validatePassword(String password, String confirmPassword) {
        if (!password.equals(confirmPassword)) {
            throw new CustomException(ErrorCode.PASSWORD_MISMATCH);
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

    public boolean loginWithSession(String email, String password, HttpServletRequest request) {
        User user = userRepository.findByEmail(email);
        if (user == null || !passwordEncoder.matches(password, user.getPassword())) {
            return false;
        }

        HttpSession oldSession = request.getSession(false);
        if (oldSession != null) {
            System.out.println("invalidate old session");
            oldSession.invalidate();
        }

        // 새 세션 생성
        HttpSession session = request.getSession(true);
        session.setAttribute("userId", user.getId());
        session.setAttribute("email", user.getEmail());
        session.setAttribute("role", user.getRole());
        session.setMaxInactiveInterval(30 * 60);

        return true;
    }

    public void logout(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
        }
    }

    public User getLoggedInUser(HttpServletRequest request) {
        HttpSession session = request.getSession(false);

        if (session == null) {
            throw new CustomException(ErrorCode.SESSION_INVALID);

        }

        Long userId = (Long) session.getAttribute("userId");
        if (userId == null) {
            throw new CustomException(ErrorCode.SESSION_INVALID);
        }

        User user = userRepository.findById(userId).orElse(null);
        if (user == null) {
            throw new CustomException(ErrorCode.USER_NOT_FOUND);
        }

        return user;
    }

    // 0. 로그인 요청
    // 1. redis에 세션생성 key : value(생성시각, 마지막접근시각, 유저아이디)
    // 2. 쿠키에 세션key를 담아서 전달
    // 3. 세션아이디 쿠키전달

    // 4. 유저요청시 redis 조회 후 유저 검증
    // 4-1. 클라이언트가 가진 sessionId와 redis가 가진 sessionId 비교 검증 (세션id를 탈취하면? 위장가능한거아님?)
    // 4-2. 클라이언트가 가진 sessionId가 맞으면 요청처리해줌 / 틀리면 예외처리
    // 5. 로그아웃시 세션제거

    // 6. 세션만료시 세션삭제
    // 7. 사용자움직임에 따라 세션 갱신?
}
