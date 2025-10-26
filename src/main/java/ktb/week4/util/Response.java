package ktb.week4.util;

import ktb.week4.util.exception.ErrorCode;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;

@NoArgsConstructor
@AllArgsConstructor
@Getter
public class Response<T> {

    private Boolean success;
    private String message;
    private T data;

    public static <T> Response<T> success(String message, T data) {
        return new Response<>(true, message,  data);
    }

    public static Response<String> fail(ErrorCode errorCode) {
        String message = errorCode.name();
        return new Response<>(false, message, null);
    }

}
