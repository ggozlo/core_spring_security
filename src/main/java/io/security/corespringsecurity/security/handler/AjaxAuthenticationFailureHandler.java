package io.security.corespringsecurity.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AjaxAuthenticationFailureHandler implements AuthenticationFailureHandler {
// ajax 인증 실패시에 동작할 핸들러, json 으로 반환

    private ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {

        String errorMsg = "Invalid Username or Password";
        // 반환할 에러메세지지

       response.setStatus(HttpStatus.UNAUTHORIZED.value());
        // 반환할 Http 상태값, 401
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        if(e instanceof BadCredentialsException) {
            errorMsg = "Invalid Username or Password";
        } else if(e instanceof DisabledException) {
            errorMsg = "Locked";
        } else if (e instanceof CredentialsExpiredException) {
            errorMsg = "Expired password";
        }

        objectMapper.writeValue(response.getWriter(), errorMsg);
        // 인증실패 메세지를 JSON 바디에 담아서 전송
    }
}
