package ktb.week4.comment;

public class CommentDto {
    public record CommentCreateRequest(
            String content
    ) {}

    public record CommentUpdateRequest(
            String content
    ) {}
}
