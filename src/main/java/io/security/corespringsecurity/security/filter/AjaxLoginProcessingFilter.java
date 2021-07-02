package io.security.corespringsecurity.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.corespringsecurity.domain.AccountDto;
import io.security.corespringsecurity.security.token.AjaxAuthenticationToken;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {
    // Ajax 로그인을 위한 커스텀 필터

    private ObjectMapper objectMapper = new ObjectMapper();
    // JSON 파싱을 위한 오브젝트 매퍼

    public AjaxLoginProcessingFilter() {
        super(new AntPathRequestMatcher("/api/login"));
    }
    // 생성자에서 부모클래스의 생성자에 AntPathRequestMatcher 를 변수로 생성, 그 인자를 작동 조건 url 로 지정하여
    // 사용자가 조건에 맞게 요청하였다면 이 필터가 동작하게 됨


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        if(!isAjax(request)) {
            throw new IllegalStateException("Authentication is not supported");
        } // 우선 ajax 인지 검사한다

        AccountDto accountDto = objectMapper.readValue(request.getReader(), AccountDto.class);
        // JSON 의 본문 POST 를 가져와서 Dto 로 매핑

        if(StringUtils.isEmpty(accountDto.getUsername()) || StringUtils.isEmpty(accountDto.getPassword())) {
            throw new IllegalStateException("username or Password is empty");
        }
        // 입력 확인

        AbstractAuthenticationToken token = new AjaxAuthenticationToken(accountDto.getUsername(), accountDto.getPassword());
        // 인증 처리를 위한 토큰을 생성

        return super.getAuthenticationManager().authenticate(token);
        // 인증 매니저를 호출하여 인증 메서드를 호출
    }

    private boolean isAjax(HttpServletRequest request) {
    // 요청이 ajax 방식인시 검사하는 메서드
        if("XMLHttpRequest".equals(request.getHeader("X-Requested-With"))) {
            return true;
        } // 요청의 헤더에 XMLHttpRequest 가 있다면 ajax
        return false;
        // 없다면 아님
    }
}
