package ktb.week4.legal;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

@Controller
@RequestMapping("/legal")
@RequiredArgsConstructor
public class LegalController {

    private static final String TERMS_FILE = "src/main/resources/templates/legal/terms.md";
    private static final String PRIVACY_FILE = "src/main/resources/templates/legal/privacy.md";

    private final LegalService legalService;

    @SneakyThrows
    @GetMapping("/terms")
    public String terms(Model model) {

        String body = legalService.markdownToHtml(Files.readString(Path.of(TERMS_FILE)));


        model.addAttribute("title", "이용약관");
        model.addAttribute("canonical", "/legal/terms");
        model.addAttribute("lang", "ko");
        model.addAttribute("version", "2025-10-01");
        model.addAttribute("lastUpdated", "2025-10-01");
        model.addAttribute("body", body);
        return "legal/terms";
    }

    @GetMapping("/privacy")
    public String privacy(Model model) throws IOException {

        String body = legalService.markdownToHtml(Files.readString(Path.of(PRIVACY_FILE)));

        model.addAttribute("title", "개인정보처리방침");
        model.addAttribute("canonical", "/legal/privacy");
        model.addAttribute("lang", "ko");
        model.addAttribute("version", "2025-10-01");
        model.addAttribute("lastUpdated", "2025-10-01");
        model.addAttribute("body", body);
        return "legal/privacy";
    }
}
