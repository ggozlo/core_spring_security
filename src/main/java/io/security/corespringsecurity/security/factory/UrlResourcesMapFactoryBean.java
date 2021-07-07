package io.security.corespringsecurity.security.factory;


import io.security.corespringsecurity.service.SecurityResourceService;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.LinkedHashMap;
import java.util.List;

public class UrlResourcesMapFactoryBean implements FactoryBean<LinkedHashMap<RequestMatcher, List<ConfigAttribute>>> {
    // db로 부터 자원들과 매핑된 권한정보를 가져와서 UrlFilterInvocationSecurityMetadataSource 에 전달하는 클래스

    private SecurityResourceService securityResourceService;

    public void setSecurityResourceService(SecurityResourceService securityResourceService) {
        this.securityResourceService = securityResourceService;
    }

    private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> resourceMap;


    @Override
    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getObject() throws Exception {

        if(resourceMap == null) {
            init();
        }

        return resourceMap;
    }

    private void init() {
        resourceMap = securityResourceService.getResourceList();
    }

    @Override
    public Class<?> getObjectType() {
        return LinkedHashMap.class;
    } //

    @Override
    public boolean isSingleton() {
//        return FactoryBean.super.isSingleton();
        return true;
    } // 싱글톤으로 관리
}
