package io.security.corespringsecurity.repository;

import io.security.corespringsecurity.domain.entity.RoleHierarchy;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RoleHierarchyRepository extends JpaRepository<RoleHierarchy, Long> {

    public RoleHierarchy findByChildName(String roleName);
}
