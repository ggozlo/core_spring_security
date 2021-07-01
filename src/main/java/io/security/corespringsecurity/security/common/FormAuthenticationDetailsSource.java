package io.security.corespringsecurity.security.common;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;

@Component
public class FormAuthenticationDetailsSource implements AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> {
    // WebAuthenticationDetails 타입의 객체를 생성해주는 역할의 클래스를 구현한 클래스
    // source 클래스를 구현, 요청 서블릿을 받아 인증 세부정보 클래스를 생성하여 반환하도록 구현
    // Bean 으로 등록하여 싱글톤 타입으로 관리된다.
    @Override
    public WebAuthenticationDetails buildDetails(HttpServletRequest request) {
        return new FormWebAuthenticationDetails(request);
    }
}
