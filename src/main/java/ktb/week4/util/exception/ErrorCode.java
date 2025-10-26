package ktb.week4.util.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@AllArgsConstructor
@Getter
public enum ErrorCode {

    /** user **/
    USER_NOT_FOUND(HttpStatus.NOT_FOUND, "유저를 찾을수 없습니다."),


    /** post **/
    POST_NOT_FOUND(HttpStatus.NOT_FOUND, "게시글을 찾을 수 없습니다.");


    /** comment **/


    /** postImage **/


    /** image **/


    /** userPostLike **/



    private final HttpStatus status;
    private final String message;




}
