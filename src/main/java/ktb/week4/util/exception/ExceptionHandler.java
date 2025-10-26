package ktb.week4.util.exception;


import ktb.week4.util.Response;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestControllerAdvice;


@RestControllerAdvice
public class ExceptionHandler {

    @org.springframework.web.bind.annotation.ExceptionHandler(CustomException.class)
    public ResponseEntity<?> handleCustomException(CustomException e) {
        ErrorCode errorCode = e.getErrorCode();
        return new ResponseEntity<>(Response.fail(errorCode), errorCode.getStatus());

    }
}

