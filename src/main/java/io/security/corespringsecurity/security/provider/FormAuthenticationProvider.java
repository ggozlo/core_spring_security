package io.security.corespringsecurity.security.provider;

import io.security.corespringsecurity.security.common.FormWebAuthenticationDetails;
import io.security.corespringsecurity.security.service.AccountContext;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
public class FormAuthenticationProvider implements AuthenticationProvider {

    private UserDetailsService userDetailsService;

    private PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 로그인 정보와 토큰 인증을 위한 로직 구현

        String username = authentication.getName();
        String password = (String) authentication.getCredentials();
        // 로그인 정보들을 받는다

        AccountContext accountContext = (AccountContext) userDetailsService.loadUserByUsername(username);
        // 사용자 아이디로 userDetail 타입의 객체를 꺼내온다, 없으면 오류, 아이디 검증됨

        if(!passwordEncoder.matches(password, accountContext.getPassword() )) {
            throw new BadCredentialsException("Invalid Password");
            //throw new BadCredentialsException("BadCredentialsException");
        } // 꺼내온 토큰과 받은 패스워드와 일치하는지 확인, 암호화 때문에 인코더로


        FormWebAuthenticationDetails details = (FormWebAuthenticationDetails) authentication.getDetails();
        // 로그인 인증객체에서 세부정보 클래스도 추출
        String secretKey = details.getSecretKey();
        // 인자 추출

        if(secretKey == null || !secretKey.equals("secret")) {
            throw new IllegalArgumentException("invalid Secret");
        } // 세부 정보에 대한 인증 로직

        UsernamePasswordAuthenticationToken token =
                new UsernamePasswordAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());
        // 일치하다면 해당 코드까지 도달 인증 완료후 반환을 위한 인증토큰 생성
       return token;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        // 변수로 받은 인증 객체와 내부의 토큰의 타입이 같을때 인증처리가 되도록 구현
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
        //return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    @Autowired
    public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Autowired
    public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }
}
