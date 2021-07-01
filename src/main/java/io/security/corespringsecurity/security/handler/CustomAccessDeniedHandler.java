package io.security.corespringsecurity.security.handler;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class CustomAccessDeniedHandler implements AccessDeniedHandler {
// 인가 거부시의 동작할 핸들러 생성
    private String errorPage;
    // 인가 거부시의 거부된 경로를 필드값으로 설정
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException exception) throws IOException, ServletException {

        String deniedUrl = errorPage + "?exception=" + exception.getMessage();
        // 거부된 경로에 예외 메시지를 파라미터로 추가함

        response.sendRedirect(deniedUrl);
        // 추가된 경로로 리다이렉트트
    }

    public void setErrorPage(String errorPage) {
        this.errorPage = errorPage;
    } // 경로 수정자

}
