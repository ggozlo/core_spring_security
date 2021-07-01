package io.security.corespringsecurity.security.handler;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {

        String errorMessage = "Invalid Username or Password";

        if(exception instanceof BadCredentialsException) {
            errorMessage = "Invalid Username or Password";
        } else if(exception instanceof InsufficientAuthenticationException) {
            errorMessage = "Invalid Secret Key";
        } // 예외별 에러메세지를 지정

        setDefaultFailureUrl("/login?error=true&exception="+ errorMessage);
        // 실패 url 을 설정
        super.onAuthenticationFailure(request, response, exception);
        // 부모객체의 실패 핸들러를 실행시킴
    }
}
