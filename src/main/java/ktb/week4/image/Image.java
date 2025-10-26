package ktb.week4.image;

import jakarta.persistence.*;
import ktb.week4.util.BaseEntity;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "images")
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
public class Image extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(columnDefinition = "BIGINT UNSIGNED")
    private Long id;

    private String fileName;

    private String fileType;

    private Long fileSize; // byte

    private String fileUrl;

    private Boolean isDeleted;

    @Builder
    private Image(String fileName, String fileType, Long fileSize, String fileUrl) {
        this.fileName = fileName;
        this.fileType = fileType;
        this.fileSize = fileSize;
        this.fileUrl = fileUrl;
        this.isDeleted = false;
    }

    protected void updateIsDelete() {
        this.isDeleted = true;
    }

}
