package io.security.corespringsecurity.security.common;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AjaxLoginAuthenticationEntryPoint implements AuthenticationEntryPoint {
    // 미인증 사용자가 인증이 필요한 자원에 접근할때 예외필터가 동작시키는  클래스

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
    // 이 메서드에서 미인증 예외 이후의 에러를 처리하고 클라이언트에게 반환
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "unAuthorized");
            // 클라이언트 에게 미인증 오류와 메세지를 보냄
    }
}
