package io.security.corespringsecurity.security.service;

import io.security.corespringsecurity.domain.Account;
import io.security.corespringsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service("userDetailService")
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
// 로그인을 구형하기 위한 UserDetailsService 인터페이스를 상속한 클래스

    private final UserRepository userRepository;
    // 로그인 정보와 대조하기 위해 DAO 를 의존함

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
    // 사용자 정보를 탐색하고, 사용자 객체를 반환하는 메서드 구현

        Account account = userRepository.findByUsername(s);
        // 받은 변수로 계정 검색

        if(account == null) {
            throw new UsernameNotFoundException("UsernameNotFoundException");
        } // 일치하는 계정이 없다면 오류 발생생

        List<GrantedAuthority> roles = new ArrayList<>();
        roles.add(new SimpleGrantedAuthority(account.getRole()));
        // UserDetailsService 스펙에 맞추기 위해 GrantedAuthority 타입의 리스트에 SimpleGrantedAuthority 구현체로
        // 배열을 생성

        AccountContext accountContext = new AccountContext(account, roles );
        // account 를 UserDetailsService 타입으로 래핑 하여 반환
        return accountContext;
    }
}
