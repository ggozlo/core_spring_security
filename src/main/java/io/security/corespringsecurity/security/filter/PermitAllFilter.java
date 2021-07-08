package io.security.corespringsecurity.security.filter;

import org.springframework.security.access.SecurityMetadataSource;
import org.springframework.security.access.intercept.AbstractSecurityInterceptor;
import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class PermitAllFilter extends FilterSecurityInterceptor {
// 특정 자원에 대한 필터체인을 들어가지 않도록 하는 필터인터셉터

        private static final String FILTER_APPLIED = "__spring_security_filterSecurityInterceptor_filterApplied";
        private boolean observeOncePerRequest = true;

    private List<RequestMatcher> permitAllRequestMatchers = new ArrayList<>();
    // permitAll 을 적용할 자원들의 모음

        public PermitAllFilter(String ... permitAllResources) {
        // 생성자, permitAll 을 적용할 자원들을 받는다
            for (String resource : permitAllResources) {
                permitAllRequestMatchers.add(new AntPathRequestMatcher(resource));
            } // for 문으로 구현체 AntPathRequestMatcher 으로 초기화 한다.

        }

        @Override
        protected InterceptorStatusToken beforeInvocation(Object object) {
        // 다음 필터 호출전에 실행, object 는 url 방식에선 FilterInvocation 타입

            boolean permitAll = false;
            // 플래그 기본값은 실패
           HttpServletRequest request = ((FilterInvocation) object).getRequest();
            // FilterInvocation 타입으로 형변환 하여 요청정보 추출

            for (RequestMatcher requestMatcher : permitAllRequestMatchers) {
                if (requestMatcher.matches(request)) {
                    permitAll = true;
                    break;
                } // 가지고있는 permitAll 대상 자원들과 비교하여 일치하면 true
            }

            if (permitAll) {
                return null;
            } // 플래그가 true 면 null을 반환시켜 권한심사를 하지않음

            return super.beforeInvocation(object);
            // 아니면 부모클래스로 넘겨서 권한심사를 받게됨
        }



        public void invoke(FilterInvocation fi) throws IOException, ServletException {
            if (fi.getRequest() != null && fi.getRequest().getAttribute("__spring_security_filterSecurityInterceptor_filterApplied") != null && this.observeOncePerRequest) {
                fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
            } else {
                if (fi.getRequest() != null && this.observeOncePerRequest) {
                    fi.getRequest().setAttribute("__spring_security_filterSecurityInterceptor_filterApplied", Boolean.TRUE);
                }

                InterceptorStatusToken token = super.beforeInvocation(fi);

                try {
                    fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
                } finally {
                    super.finallyInvocation(token);
                }

                super.afterInvocation(token, (Object)null);
            }

        }



}
