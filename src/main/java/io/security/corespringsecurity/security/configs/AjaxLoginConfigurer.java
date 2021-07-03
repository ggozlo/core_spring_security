package io.security.corespringsecurity.security.configs;

import io.security.corespringsecurity.security.filter.AjaxLoginProcessingFilter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

public final class AjaxLoginConfigurer<H extends HttpSecurityBuilder<H>> extends
        AbstractAuthenticationFilterConfigurer<H, AjaxLoginConfigurer<H>, AjaxLoginProcessingFilter> {
// AbstractHttpConfigurer 를 상속받은 AbstractAuthenticationFilterConfigurer 를 확장하여 DSL 구현
// HttpSecurity 를 설정하는 메서드의 API 부분을 독립시켜 구현할수 있다.

    private AuthenticationSuccessHandler successHandler;
    private AuthenticationFailureHandler failureHandler;
    private AuthenticationManager authenticationManager;

    public AjaxLoginConfigurer() {
        super(new AjaxLoginProcessingFilter(), null);
    } // 생성자에선 필터를 생성하여 부모클래스에 전달

    @Override
    public void init(H http) throws Exception {
        super.init(http);
    }

    @Override
    public void configure(H http) throws Exception {

        if(authenticationManager == null) {
            authenticationManager = http.getSharedObject(AuthenticationManager.class);
        } // 인증관리자가 없다면  HttpSecurityBuilder 가 지원하는 고유 오브젝트 에서 에서 맞는 클래스타입의 객체를 끌어옴

        getAuthenticationFilter().setAuthenticationManager(authenticationManager);
        getAuthenticationFilter().setAuthenticationSuccessHandler(successHandler);
        getAuthenticationFilter().setAuthenticationFailureHandler(failureHandler);
        // 부모객체에 저장된 필터에 핸들러들을 입력

        SessionAuthenticationStrategy sessionAuthenticationStrategy = http
                .getSharedObject(SessionAuthenticationStrategy.class);
        if (sessionAuthenticationStrategy != null) {
            getAuthenticationFilter().setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
        } // SessionAuthenticationStrategy 세션인증전략 객체를 시큐리티빌더 에서 가져와 null 이 아니면 필터에 적용
        RememberMeServices rememberMeServices = http.getSharedObject(RememberMeServices.class);
        if(rememberMeServices != null) {
            getAuthenticationFilter().setRememberMeServices(rememberMeServices);
        }

        http.setSharedObject(AjaxLoginProcessingFilter.class, getAuthenticationFilter());
        // 공유객체에 인증 필터를 저장 (공유객체는 클래스타입을 Key 로 저장하는듯), 생성시에 넣은 필터를 꺼내옴
        http.addFilterBefore(getAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        // 필터의 위치를 지정하여 추가
    }

    public AjaxLoginConfigurer<H> successHandlerAjax(AuthenticationSuccessHandler successHandler) {
        this.successHandler = successHandler;
        return this;
    }
    public AjaxLoginConfigurer<H> failureHandlerAjax(AuthenticationFailureHandler failureHandler) {
        this.failureHandler = failureHandler;
        return this;
    }
    public AjaxLoginConfigurer<H> setAuthenticationManager(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
        return this;
    }
    // 외부에서 핸들러를 전달해주는 메서드들

    @Override
    protected RequestMatcher createLoginProcessingUrlMatcher(String s) {
        return new AntPathRequestMatcher(s, "POST");
    }
    // 필터 동작조건 URL 패턴을 주입받는 메서드
}
