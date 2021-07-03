package io.security.corespringsecurity.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.corespringsecurity.domain.Account;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AjaxAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
// AJAX 인증처리 성공의 반환을 위한 핸들러 얘가 JSON 을 반환시킨다

    private ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        Account account = (Account) authentication.getPrincipal();

        response.setStatus(HttpStatus.OK.value());
        // 응답시의 HttpStatus 값을 설정 OK = 200
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        // 반환타입은 JSON

        objectMapper.writeValue(response.getWriter(), account);
        // objectMapper 의 writeValue 메서드로  response 에  account 객체의 내용을 매핑
    }
}
