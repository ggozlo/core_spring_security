package io.security.corespringsecurity.repository;

import io.security.corespringsecurity.domain.entity.AccessIp;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AccessIpRepository extends JpaRepository<AccessIp, Long> {

    AccessIp findByIpAddress(String IpAddress);
}
