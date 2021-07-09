package io.security.corespringsecurity.service.impl;

import io.security.corespringsecurity.domain.entity.RoleHierarchy;
import io.security.corespringsecurity.repository.RoleHierarchyRepository;
import io.security.corespringsecurity.service.RoleHierarchyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Iterator;
import java.util.List;

@Service
public class RoleHierarchyServiceImpl implements RoleHierarchyService {

    @Autowired
    private RoleHierarchyRepository roleHierarchyRepository;

    @Transactional
    @Override
    public String findAllHierarch() {
        List<RoleHierarchy> rolesHierarchy = roleHierarchyRepository.findAll();

        Iterator<RoleHierarchy> itr = rolesHierarchy.iterator();
        StringBuilder concatdRoles = new StringBuilder();

        while (itr.hasNext()) {
            RoleHierarchy roleHierarchy = itr.next();
            if (roleHierarchy.getParentName() != null) {
                concatdRoles.append(roleHierarchy.getParentName().getChildName());
                concatdRoles.append(" > ");
                concatdRoles.append(roleHierarchy.getChildName());
                concatdRoles.append("\n");
            }
        }
        return concatdRoles.toString();
    } // 권한계층의 표현식을 문자열로 작성시키는 메서드
}
