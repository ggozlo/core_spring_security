package io.security.corespringsecurity.security.handler;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class FormAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
// AuthenticationSuccessHandler 를 성공 핸들러 구현체 SimpleUrlAuthenticationSuccessHandler 클래스를 확장하여 직접 구현

    private RequestCache requestCache = new HttpSessionRequestCache();
    // 인증요구 전에 저장된 사용자의 요청내용이 있음

    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    // 요청정보로 리다이렉트 하기 위한 전략 클래스

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        super.setDefaultTargetUrl("/");

        SavedRequest savedRequest = requestCache.getRequest(request, response);
        // 인증 전의 요청을 가져옴
        if(savedRequest != null) {
            String targetUrl = savedRequest.getRedirectUrl(); // url 추출
            redirectStrategy.sendRedirect(request, response, targetUrl); // 리다이렉트 실행
        }
        else {
            redirectStrategy.sendRedirect(request, response, getDefaultTargetUrl());
            // 요청 정보가 남아있지 않다면 설정된 기본 url 로
        }
    }
}
