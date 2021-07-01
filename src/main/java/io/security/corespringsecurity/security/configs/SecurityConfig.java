package io.security.corespringsecurity.security.configs;

import io.security.corespringsecurity.security.provider.FormAuthenticationProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
@Slf4j
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AuthenticationDetailsSource authenticationDetailsSource;
    // authenticationDetailsSource 클래스를 의존성 주입

    @Autowired
    private AuthenticationSuccessHandler customAuthenticationSuccessHandler;

    @Autowired
    private AuthenticationFailureHandler customAuthenticationFailureHandler;


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(authenticationProvider());
        // 스프링 서비스의 인증관리자가 특정 프로바이더를 사용하도록 지정
        
        // auth.userDetailsService(userDetailsService);
        // 직접 구현한 userDetailsService 를 주입받아 사용하도록 설정
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        return new FormAuthenticationProvider();
        // 생성한 커스텀 프로바이더 클래스를 빈으로 등록
    }

    @Bean // 메서드 빈 타입의 패스워드 인코더, 설정된 암호화 방식을 지원한다.
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
        // 여러개의 인코더 유행이 선언되어 있다
        // 상황에 맞게 사용이 가능하다
        // 스프링 시큐리티 5.0 이전 기본 인코더는 noOp (평문), 현재는 BCrypto
    }


    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
        // 시큐리티의 인증, 인가 검사 무시 대상을 경로로 지정, 요청경로, 스태틱 자원들의 일반적인 위치들 로 지정, (JS, CSS, 등,...)
        // 보안필터를 아에 거치지 않음

    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/","/users","/users/login/**", "/login*").permitAll() // 보안필터를 거쳐야함 들어감
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .anyRequest().authenticated()

        .and()
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .authenticationDetailsSource(authenticationDetailsSource)
                // 주입받은 authenticationDetailsSource 를 authenticationDetailsSource api 에 적용하여 동작하도록 설정
                .defaultSuccessUrl("/")
                .successHandler(customAuthenticationSuccessHandler) // 성공 핸들러는 기본 성공 Url API 설정보다 아래에
                .failureHandler(customAuthenticationFailureHandler)
                .permitAll()
        ;
    }
}
