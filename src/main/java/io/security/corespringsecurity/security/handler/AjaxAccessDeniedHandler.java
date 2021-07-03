package io.security.corespringsecurity.security.handler;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AjaxAccessDeniedHandler  implements AccessDeniedHandler {
    // 인가 예외시 동작
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e) throws IOException, ServletException {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Ajax Access is denied");
            // 클라이언트에게 인가 오류코드와 메세지 전달
    }
}
