package io.security.corespringsecurity.service;

import io.security.corespringsecurity.domain.entity.Resources;
import io.security.corespringsecurity.repository.AccessIpRepository;
import io.security.corespringsecurity.repository.ResourcesRepository;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.stream.Collectors;

public class SecurityResourceService {
// db에 있는 자원데이터를 반환하기 위한


    private ResourcesRepository resourcesRepository;
    private AccessIpRepository accessIpRepository;

    public SecurityResourceService(ResourcesRepository resourcesRepository, AccessIpRepository accessIpRepository) {
        this.resourcesRepository = resourcesRepository;
        this.accessIpRepository = accessIpRepository;
    }

    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getResourceList() {
        // db에 등록된 자원들과 그 권한정보를 반환하는 메서드

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


    public List<String > getAccessList() {
        // ip 리스트를 반환
        List<String> accessIpList = accessIpRepository.findAll().stream().map(accessIp -> accessIp.getIpAddress()).collect(Collectors.toList());

        return accessIpList;
    }
}
