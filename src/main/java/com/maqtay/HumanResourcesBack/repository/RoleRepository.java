package com.maqtay.HumanResourcesBack.repository;

import com.maqtay.HumanResourcesBack.models.ERole;
import com.maqtay.HumanResourcesBack.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole name);
}
