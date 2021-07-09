package io.security.corespringsecurity.security.init;

import io.security.corespringsecurity.domain.entity.RoleHierarchy;
import io.security.corespringsecurity.service.RoleHierarchyService;
import io.security.corespringsecurity.service.impl.RoleHierarchyServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.stereotype.Component;

@Component
public class SecurityInitializer implements ApplicationRunner {


    @Autowired
    private RoleHierarchyService roleHierarchyService;

    @Autowired
    private RoleHierarchyImpl roleHierarchy;

    @Override
    public void run(ApplicationArguments args) throws Exception {

        String allHierarch = roleHierarchyService.findAllHierarch(); // 계층 표현 문자열로 가져옴
        roleHierarchy.setHierarchy(allHierarch); // 권한 계층을 보터에 적용시킴
    }

}
