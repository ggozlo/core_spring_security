package io.security.corespringsecurity.security.voter;

import io.security.corespringsecurity.repository.AccessIpRepository;
import io.security.corespringsecurity.service.SecurityResourceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import java.util.Collection;
import java.util.List;


public class IpAccessVoter implements AccessDecisionVoter<Object> {
    // 요청한 ip 가 맞는 ip 인지 확인하여 맞다면 투표 기권 으로 넘기고
    // 아니라면 예외를 발생시켜 접속을 차단함

    private SecurityResourceService securityResourceService;

    public IpAccessVoter(SecurityResourceService securityResourceService) {
        this.securityResourceService = securityResourceService;
    }

    @Override
    public boolean supports(ConfigAttribute configAttribute) {
        return true;
    }

    @Override // 투표대상인지 판별
    public boolean supports(Class<?> aClass) {
        return true;
    }

    @Override
    public int vote(Authentication authentication, Object o, Collection<ConfigAttribute> collection) {
        // 사용자 인증정보, 요청정보(FilterInvocation), 대상 자원에 필요한 권한정보 를 받아서 판단한다.

        WebAuthenticationDetails details = (WebAuthenticationDetails) authentication.getDetails(); // 사용자의 ip 정보 포함
        String remoteAddress = details.getRemoteAddress(); // ip 주소 추출

        List<String> accessList = securityResourceService.getAccessList();
        // 접근 허용 ip 리스트를 반환

        int result = ACCESS_DENIED; // 접근거부를 반환

        for (String ipAddress : accessList) {
            if (remoteAddress.equals(ipAddress)) {
                return ACCESS_ABSTAIN; // 접근 허가 ip 가 있다면 접근 보류를 반환
            }
        }

        if (result == ACCESS_DENIED) {
            throw new AccessDeniedException("Invalid IpAddress");
        }

        return result;
    }

}
