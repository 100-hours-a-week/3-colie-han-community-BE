package ktb.week4.user;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import ktb.week4.Login.JwtProvider;
import ktb.week4.Login.refreshToken.RefreshToken;
import ktb.week4.Login.refreshToken.RefreshTokenRepository;
import ktb.week4.image.Image;
import ktb.week4.image.ImageService;
import ktb.week4.util.exception.CustomException;
import ktb.week4.util.exception.ErrorCode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.time.Instant;
import java.util.Map;

import static ktb.week4.user.UserDto.*;


@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final ImageService imageService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtProvider jwtProvider;

    private static final int ACCESS_TOKEN_EXPIRATION = 15 * 60; // 15분
    private static final int REFRESH_TOKEN_EXPIRATION = 14 * 24 * 3600; // 14일


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

    public User getUser(Long userId) {
        return userRepository.findById(userId).orElse(null);
    }

    @Transactional
    public String loginWithJwt(String email, String password, HttpServletResponse response) {
        User user = userRepository.findByEmail(email).orElse(null);

        if (user == null || !passwordEncoder.matches(password, user.getPassword())) {
            throw new CustomException(ErrorCode.PASSWORD_MISMATCH);
        }

        refreshTokenRepository.deleteByUserId(user.getId());

        var tokenResponse = generateAndSaveTokens(user);
        addTokenCookies(response, tokenResponse);
        return tokenResponse.accessToken();
    }

    @Transactional
    public TokenResponse refreshTokens(String refreshToken, HttpServletResponse response) {
        var parsedRefreshToken = jwtProvider.parse(refreshToken);

        RefreshToken entity = refreshTokenRepository.findByTokenAndRevokedFalse(refreshToken).orElse(null);

        if (entity == null || entity.getExpiresDate().isBefore(Instant.now())) {
            return null;
        }

        Long userId = Long.valueOf(parsedRefreshToken.getBody().getSubject());
        User user = userRepository.findById(userId).orElse(null);

        if (user == null) {
            return null;
        }

        String newAccessToken = jwtProvider.createAccessToken(user.getId(), user.getEmail());

        addTokenCookie(response, "accessToken", newAccessToken, ACCESS_TOKEN_EXPIRATION);

        return new TokenResponse(newAccessToken, refreshToken);
    }

    public void logoutUser(HttpServletResponse response) {
        addTokenCookie(response, "accessToken", null, 0);
        addTokenCookie(response, "refreshToken", null, 0);
    }

    private TokenResponse generateAndSaveTokens(User user) {
        String accessToken = jwtProvider.createAccessToken(user.getId(), user.getEmail());
        String refreshToken = jwtProvider.createRefreshToken(user.getId());

        RefreshToken refreshEntity = new RefreshToken();
        refreshEntity.setUserId(user.getId());
        refreshEntity.setToken(refreshToken);
        refreshEntity.setExpiresDate(Instant.now().plusSeconds(REFRESH_TOKEN_EXPIRATION));
        refreshEntity.setRevoked(false);
        refreshTokenRepository.save(refreshEntity);

        return new TokenResponse(accessToken, refreshToken);
    }

    private void addTokenCookies(HttpServletResponse response, TokenResponse tokenResponse) {
        addTokenCookie(response, "accessToken", tokenResponse.accessToken(), ACCESS_TOKEN_EXPIRATION);
        addTokenCookie(response, "refreshToken", tokenResponse.refreshToken(), REFRESH_TOKEN_EXPIRATION);
    }

    private void addTokenCookie(HttpServletResponse response, String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(false);
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);
        response.addCookie(cookie);
    }

    public record TokenResponse(String accessToken, String refreshToken) { }

}
