package ktb.week4.image;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

@Service
@RequiredArgsConstructor
public class ImageService {
    private final ImageRepository imageRepository;
    private final Path rootLocation = Paths.get("uploads").toAbsolutePath().normalize();

    // 허용하는 파일 타입
    private static final Set<String> ALLOWED_CONTENT_TYPES = Set.of(
            "image/jpeg", "image/jpg", "image/png", "image/gif", "image/webp"
    );

    // 파일 최대 사이즈 10MB
    private static final long DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024L;

    @Transactional
    public Image uploadImage(MultipartFile file) {
        validateFileNotEmpty(file);
        validateContentType(file);
        validateSize(file);

        String safeFileName = sanitizeFileName(file.getOriginalFilename());
        String ext = extractExtension(safeFileName);
        String storedName = UUID.randomUUID().toString() + (ext.isEmpty() ? "" : "." + ext);

        Path destination = resolveDestinationPath(storedName);

        try (InputStream in = file.getInputStream()) {
            Files.copy(in, destination);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        String url = getUrl(storedName);
        Image image = Image.builder()
                .fileName(safeFileName)
                .fileSize(file.getSize())
                .fileType(file.getContentType())
                .fileUrl(url)
                .build();
        imageRepository.save(image);
        return image;
    }

    @Transactional
    public void updateIsDeleted(Image image) {
        image.updateIsDelete();
    }

    private void validateFileNotEmpty(MultipartFile file) {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("file is empty");
        }
    }

    private void validateContentType(MultipartFile file) {
        String contentType = file.getContentType();
        if (contentType == null || !ALLOWED_CONTENT_TYPES.contains(contentType.toLowerCase(Locale.ROOT))) {
            throw new IllegalArgumentException(String.format("invalid content type: %s", contentType));
        }
    }

    private void validateSize(MultipartFile file) {
        if (file.getSize() > DEFAULT_MAX_FILE_SIZE) {
            throw new IllegalArgumentException("file size too large");
        }

    }

    private String sanitizeFileName(String originalFilename) {
        if (originalFilename == null) return "unknown";

        String cleaned = Paths.get(originalFilename).getFileName().toString();
        cleaned = cleaned.trim();
        cleaned = cleaned.replaceAll("[\\\\/:*?\"<>|]+", "");
        return cleaned;
    }

    private String extractExtension(String fileName) {
        int idx = fileName.lastIndexOf('.');
        if (idx <= 0 || idx == fileName.length() - 1) return "";
        return fileName.substring(idx + 1);
    }

    private Path resolveDestinationPath(String storedName) {
        try {
            Path destination = rootLocation.resolve(storedName).normalize().toAbsolutePath();
            if (!destination.startsWith(rootLocation)) {
                throw new IllegalArgumentException(String.format("stored name '%s' is invalid", storedName));
            }
            return destination;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private String getUrl(String storedName) {
        return "/files/" + storedName;
    }


}
