package io.security.corespringsecurity.service;

import io.security.corespringsecurity.domain.entity.Resources;
import io.security.corespringsecurity.repository.ResourcesRepository;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

public class SecurityResourceService {

    private ResourcesRepository resourcesRepository;

    public SecurityResourceService(ResourcesRepository resourcesRepository) {
        this.resourcesRepository = resourcesRepository;
    }

    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getResourceList() {

        LinkedHashMap<RequestMatcher, List<ConfigAttribute>> result = new LinkedHashMap<>();

        List<Resources> resourcesList = resourcesRepository.findAllResources();
        // db 에서 자원을 모두 가져옴
        resourcesList.forEach(rs-> {
            List<ConfigAttribute> configAttributeList = new ArrayList<>();

            rs.getRoleSet().forEach(role -> {
                configAttributeList.add(new SecurityConfig(role.getRoleName()));
            }); // 자원과 연관된  권한들의 이름을 추출하여 ConfigAttribute 의 구현체 SecurityConfig 을 생성하여 권한 리스트에 추가
            result.put(new AntPathRequestMatcher(rs.getResourceName()), configAttributeList);
        }); // 자원 - 권한 맵 구조로 추가

        return result;
    }


}
