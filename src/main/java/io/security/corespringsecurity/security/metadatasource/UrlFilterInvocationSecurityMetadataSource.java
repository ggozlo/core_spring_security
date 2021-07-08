package io.security.corespringsecurity.security.metadatasource;

import io.security.corespringsecurity.service.SecurityResourceService;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.http.HttpServletRequest;
import java.util.*;

public class UrlFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {
// 요청된 자원의 인가정보를 반환하기 위한 클래스

    private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap = new LinkedHashMap<>();

    private SecurityResourceService securityResourceService;

    public UrlFilterInvocationSecurityMetadataSource(LinkedHashMap<RequestMatcher, List<ConfigAttribute>> resourceMap, SecurityResourceService securityResourceService) {
        this.requestMap = resourceMap;
        this.securityResourceService = securityResourceService;
    }
    // 링크드 해시맵에 요청 주소를 키, 권한리스트를 배열로 가짐
    // 서버가 가진 자원들의 인가 정보를 보관함


    @Override
    public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {
    // 요청 주소 또는 메서드에 대한 필요 권한 컬렉션을 반환하는 메서드

        HttpServletRequest request = ((FilterInvocation) object).getRequest();
        // FilterInvocation 으로 받았다면 형변환 후 요청정보를 획득함

 //       requestMap.put(new AntPathRequestMatcher("/mypage"), Arrays.asList(new SecurityConfig("ROLE_USER")));
        // 테스트를 위하여 자원 인가 맵에 엔트리를 임의로 추가
        // SecurityConfig - ConfigAttribute 의 구현클래스

        if(requestMap != null){ // 존재 한다면
            for(Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : requestMap.entrySet()){
                // requestMap 가 존재한다면 엔트리를 하나씩 꺼내서

                RequestMatcher matcher = entry.getKey();
                if(matcher.matches(request)){
                    return entry.getValue();
                }
                // 요청정보와 엔트리의 키값이 일치하는 엔트리가 있는지 확인하여 있다면 밸류값 (인가정보) 를 반환
            }
        }
        return null;
        // 요철정보와 일치하는 엔트리가 없다면 null
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        Set<ConfigAttribute> allAttributes = new HashSet<>();

        for (Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : requestMap
                .entrySet()) {
            allAttributes.addAll(entry.getValue());
        }

        return allAttributes;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return FilterInvocation.class.isAssignableFrom(clazz);
        // 필터 동작 조건 타입 검사 매서드 FilterInvocation 으로 요청되어야함
    }

    public void reload() {
        LinkedHashMap<RequestMatcher, List<ConfigAttribute>> reloadedMap = securityResourceService.getResourceList();
        Iterator<Map.Entry<RequestMatcher, List<ConfigAttribute>>> iterator = reloadedMap.entrySet().iterator();

        requestMap.clear();

        while ((iterator.hasNext())) {
            Map.Entry<RequestMatcher, List<ConfigAttribute>> entry = iterator.next();
            requestMap.put(entry.getKey(), entry.getValue());
        }
    }
}
