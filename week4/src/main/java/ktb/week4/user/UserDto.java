package ktb.week4.user;

import jakarta.validation.constraints.*;
import org.springframework.web.multipart.MultipartFile;

public class UserDto {
    public record SignUpRequest(
            @NotBlank(message = "이메일을 입력해주세요.")
            @Email(message = "올바른 이메일 주소 형식을 입력해주세요.(예: example@example.com)")
            String email,

            @NotBlank(message = "비밀번호를 입력해주세요.")
            @Size(min = 8, max = 20, message = "비밀번호는 8자 이상, 20자 이하로 입력해주세요.")
            @Pattern(
                    regexp = "^(?=.*[A-Za-z])(?=.*\\d)(?=.*[!@#$%^&*()_+\\-={}\\[\\]:;\"'<>,.?/]).{8,20}$",
                    message = "비밀번호는 영문, 숫자, 특수문자를 각각 최소 1개 포함해야 합니다."
            )
            String password,

            @NotBlank(message = "비밀번호를 한번더 입력해주세요.")
            String confirmPassword,

            @NotBlank(message = "닉네임을 입력해주세요.")
            @Size(max = 10, message = "닉네임은 최대 10자까지 작성 가능합니다.")
            @Pattern(regexp = "^[A-Za-z0-9가-힣]+$", message = "띄어쓰기를 없애주세요")
            String nickName,

            @NotNull(message = "프로필 사진을 추가해주세요")
            MultipartFile profileImage
    ) {}

    public record UserResponse(
            Long id,
            String email,
            String nickName,
            String profileImageUrl
    ) {
        public static UserResponse from(User user) {
            return new UserResponse(
                    user.getId(),
                    user.getEmail(),
                    user.getNickName(),
                    user.getProfileImg().getFileUrl()
            );
        }
    }

    public record profileImageUpdateRequest(
            MultipartFile profileImage
    ) {}

    public record nickNameUpdateRequest(
            @NotBlank(message = "닉네임을 입력해주세요.")
            @Size(max = 10, message = "닉네임은 최대 10자까지 가능합니다.")
            String nickName
    ) {}

    public record passwordUpdateRequest(
            @NotBlank(message = "비밀번호를 입력해주세요")
            String password,
            @NotBlank(message = "비밀번호를 한번더 입력해주세요")
            String confirmPassword
    ) {}
}
