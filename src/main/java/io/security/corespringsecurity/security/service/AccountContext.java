package io.security.corespringsecurity.security.service;

import io.security.corespringsecurity.domain.Account;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

public class AccountContext extends User {
// UserDetails 인터페이스를 구현한 User 클래스를 상속받아서 사용자 계정 컨테이너를 구현
// Account 엔티티와 UserDetails 타입의 객체를 분리할수 있다

    private final Account account;


    public AccountContext(Account account, Collection<? extends GrantedAuthority> authorities) {
        super(account.getUsername(), account.getPassword(), authorities);
        this.account  = account;
    }

    public Account getAccount() {
        return account;
    }
}
