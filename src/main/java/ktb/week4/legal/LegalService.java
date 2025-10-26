package ktb.week4.legal;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import org.commonmark.node.*;
import org.commonmark.parser.Parser;
import org.commonmark.renderer.html.HtmlRenderer;


@Service
@RequiredArgsConstructor
public class LegalService {
    public String markdownToHtml(String markdown) {
        // Markdown 파서 생성
        Parser parser = Parser.builder().build();
        // org.commonmark.node.Node (CommonMark 전용 타입)
        Node document = parser.parse(markdown);
        // HTML 렌더러 생성
        HtmlRenderer renderer = HtmlRenderer.builder().build();
        // Markdown → HTML 문자열로 변환
        return renderer.render(document);
    }
}
